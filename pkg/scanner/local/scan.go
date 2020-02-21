package local

import (
	"fmt"
	"sort"
	"time"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/google/wire"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

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
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
	ftypes "github.com/aquasecurity/fanal/types"
	libDetector "github.com/aquasecurity/trivy/pkg/detector/library"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/report"
)

var SuperSet = wire.NewSet(
	analyzer.NewApplier,
	wire.Bind(new(Applier), new(analyzer.Applier)),
	ospkgDetector.SuperSet,
	wire.Bind(new(OspkgDetector), new(ospkgDetector.Detector)),
	libDetector.SuperSet,
	wire.Bind(new(LibraryDetector), new(libDetector.Detector)),
	NewScanner,
)

type Applier interface {
	ApplyLayers(imageID digest.Digest, layerIDs []string) (detail ftypes.ImageDetail, err error)
}

type OspkgDetector interface {
	Detect(imageName, osFamily, osName string, created time.Time, pkgs []ftypes.Package) (detectedVulns []types.DetectedVulnerability, eosl bool, err error)
}

type LibraryDetector interface {
	Detect(imageName, filePath string, created time.Time, pkgs []ptypes.Library) (detectedVulns []types.DetectedVulnerability, err error)
}

type Scanner struct {
	applier       Applier
	ospkgDetector OspkgDetector
	libDetector   LibraryDetector
}

func NewScanner(applier Applier, ospkgDetector OspkgDetector, libDetector LibraryDetector) Scanner {
	return Scanner{applier: applier, ospkgDetector: ospkgDetector, libDetector: libDetector}
}

func (s Scanner) Scan(target string, imageID digest.Digest, layerIDs []string, options types.ScanOptions) (report.Results, *ftypes.OS, bool, error) {
	imageDetail, err := s.applier.ApplyLayers(imageID, layerIDs)
	if err != nil {
		return nil, nil, false, xerrors.Errorf("failed to apply layers: %w", err)
	}

	var eosl bool
	var results report.Results

	if utils.StringInSlice("os", options.VulnType) {
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
			results = append(results, *result)
		}
	}

	if utils.StringInSlice("library", options.VulnType) {
		libResults, err := s.scanLibrary(imageDetail.Applications)
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
	}
	return result, eosl, nil
}

func (s Scanner) scanLibrary(apps []ftypes.Application) (report.Results, error) {
	var results report.Results
	for _, app := range apps {
		vulns, err := s.libDetector.Detect("", app.FilePath, time.Time{}, app.Libraries)
		if err != nil {
			return nil, xerrors.Errorf("failed vulnerability detection of libraries: %w", err)
		}

		results = append(results, report.Result{
			Target:          app.FilePath,
			Vulnerabilities: vulns,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
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
