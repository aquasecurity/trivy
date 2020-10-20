package local

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
	"github.com/aquasecurity/fanal/applier"
	ftypes "github.com/aquasecurity/fanal/types"
	libDetector "github.com/aquasecurity/trivy/pkg/detector/library"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// SuperSet binds dependencies for Local scan
var SuperSet = wire.NewSet(
	applier.NewApplier,
	wire.Bind(new(Applier), new(applier.Applier)),
	ospkgDetector.SuperSet,
	wire.Bind(new(OspkgDetector), new(ospkgDetector.Detector)),
	libDetector.SuperSet,
	wire.Bind(new(LibraryDetector), new(libDetector.Detector)),
	NewScanner,
)

// Applier defines operation to scan image layers
type Applier interface {
	ApplyLayers(artifactID string, blobIDs []string) (detail ftypes.ArtifactDetail, err error)
}

// OspkgDetector defines operation to detect OS vulnerabilities
type OspkgDetector interface {
	Detect(imageName, osFamily, osName string, created time.Time, pkgs []ftypes.Package) (detectedVulns []types.DetectedVulnerability, eosl bool, err error)
}

// LibraryDetector defines operation to detect library vulnerabilities
type LibraryDetector interface {
	Detect(imageName, filePath string, created time.Time, pkgs []ftypes.LibraryInfo) (detectedVulns []types.DetectedVulnerability, err error)
}

// Scanner implements the OspkgDetector and LibraryDetector
type Scanner struct {
	applier       Applier
	ospkgDetector OspkgDetector
	libDetector   LibraryDetector
}

// NewScanner is the factory method for Scanner
func NewScanner(applier Applier, ospkgDetector OspkgDetector, libDetector LibraryDetector) Scanner {
	return Scanner{applier: applier, ospkgDetector: ospkgDetector, libDetector: libDetector}
}

// Scan scans the local image and return results. TODO: fix cyclometic complexity
// nolint: gocyclo
func (s Scanner) Scan(target string, imageID string, layerIDs []string, options types.ScanOptions) (report.Results, *ftypes.OS, bool, error) {
	imageDetail, err := s.applier.ApplyLayers(imageID, layerIDs)
	if err != nil {
		switch err {
		case analyzer.ErrUnknownOS:
			log.Logger.Warn("OS is not detected and vulnerabilities in OS packages are not detected.")
		case analyzer.ErrNoPkgsDetected:
			log.Logger.Warn("No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.")
			log.Logger.Warn(`e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"`)
		default:
			return nil, nil, false, xerrors.Errorf("failed to apply layers: %w", err)
		}
	}

	var eosl bool
	var results report.Results

	if utils.StringInSlice("os", options.VulnType) && imageDetail.OS != nil {
		pkgs := imageDetail.Packages
		if options.ScanRemovedPackages {
			pkgs = mergePkgs(pkgs, imageDetail.HistoryPackages)
		}

		var result *report.Result
		result, eosl, err = s.scanOSPkg(target, imageDetail.OS.Family, imageDetail.OS.Name, pkgs)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("failed to scan OS packages: %w", err)
		}
		if result != nil {
			if options.ListAllPackages {
				sort.Slice(pkgs, func(i, j int) bool {
					return strings.Compare(pkgs[i].Name, pkgs[j].Name) <= 0
				})
				result.Packages = pkgs
			}
			results = append(results, *result)
		}
	}

	if utils.StringInSlice("library", options.VulnType) {
		libResults, err := s.scanLibrary(imageDetail.Applications, options)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, libResults...)
	}

	return results, imageDetail.OS, eosl, nil
}

func (s Scanner) scanOSPkg(target, osFamily, osName string, pkgs []ftypes.Package) (*report.Result, bool, error) {
	if osFamily == "" {
		return nil, false, nil
	}
	vulns, eosl, err := s.ospkgDetector.Detect("", osFamily, osName, time.Time{}, pkgs)
	if err == ospkgDetector.ErrUnsupportedOS {
		return nil, false, nil
	} else if err != nil {
		return nil, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	imageDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osName)
	result := &report.Result{
		Target:          imageDetail,
		Vulnerabilities: vulns,
		Type:            osFamily,
	}
	return result, eosl, nil
}

func (s Scanner) scanLibrary(apps []ftypes.Application, options types.ScanOptions) (report.Results, error) {
	var results report.Results
	for _, app := range apps {
		vulns, err := s.libDetector.Detect("", app.FilePath, time.Time{}, app.Libraries)
		if err != nil {
			return nil, xerrors.Errorf("failed vulnerability detection of libraries: %w", err)
		}

		if skipped(app.FilePath, options.SkipFiles, options.SkipDirectories) {
			continue
		}

		libReport := report.Result{
			Target:          app.FilePath,
			Vulnerabilities: vulns,
			Type:            app.Type,
		}
		if options.ListAllPackages {
			var pkgs []ftypes.Package
			for _, lib := range app.Libraries {
				pkgs = append(pkgs, ftypes.Package{
					Name:    lib.Library.Name,
					Version: lib.Library.Version,
					Layer:   lib.Layer,
				})
			}
			sort.Slice(pkgs, func(i, j int) bool {
				return strings.Compare(pkgs[i].Name, pkgs[j].Name) <= 0
			})
			libReport.Packages = pkgs
		}
		results = append(results, libReport)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}

func skipped(filePath string, skipFiles, skipDirectories []string) bool {
	for _, skipFile := range skipFiles {
		skipFile = strings.TrimLeft(filepath.Clean(skipFile), string(os.PathSeparator))
		if filePath == skipFile {
			return true
		}
	}

	for _, skipDir := range skipDirectories {
		skipDir = strings.TrimLeft(filepath.Clean(skipDir), string(os.PathSeparator))
		rel, err := filepath.Rel(skipDir, filePath)
		if err != nil {
			log.Logger.Warnf("Unexpected error while skipping directories: %s", err)
			return false
		}
		if !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}

func mergePkgs(pkgs, pkgsFromCommands []ftypes.Package) []ftypes.Package {
	// pkg has priority over pkgsFromCommands
	uniqPkgs := map[string]struct{}{}
	for _, pkg := range pkgs {
		uniqPkgs[pkg.Name] = struct{}{}
	}
	for _, pkg := range pkgsFromCommands {
		if _, ok := uniqPkgs[pkg.Name]; ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}
