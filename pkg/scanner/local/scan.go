package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/wire"
	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/policy"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/config/docker"
	_ "github.com/aquasecurity/fanal/analyzer/config/json"
	_ "github.com/aquasecurity/fanal/analyzer/config/toml"
	_ "github.com/aquasecurity/fanal/analyzer/config/yaml"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/jar"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/nuget"
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
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpm"
	"github.com/aquasecurity/fanal/applier"
	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
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

// Scanner implements the OspkgDetector and LibraryDetector
type Scanner struct {
	applier       Applier
	ospkgDetector OspkgDetector
}

// NewScanner is the factory method for Scanner
func NewScanner(applier Applier, ospkgDetector OspkgDetector) Scanner {
	return Scanner{applier: applier, ospkgDetector: ospkgDetector}
}

// Scan scans the artifact and return results.
func (s Scanner) Scan(target, versionedArtifactID string, versionedBlobIDs []string, options types.ScanOptions) (
	report.Results, *ftypes.OS, bool, error) {
	artifactDetail, err := s.applier.ApplyLayers(versionedArtifactID, versionedBlobIDs)
	switch {
	case errors.Is(err, analyzer.ErrUnknownOS):
		log.Logger.Debug("OS is not detected and vulnerabilities in OS packages are not detected.")
	case errors.Is(err, analyzer.ErrNoPkgsDetected):
		log.Logger.Warn("No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.")
		log.Logger.Warn(`e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"`)
	case err != nil:
		return nil, nil, false, xerrors.Errorf("failed to apply layers: %w", err)
	}

	var eosl bool
	var results report.Results

	// Scan OS packages and programming language dependencies
	if utils.StringInSlice(types.SecurityCheckVulnerability, options.SecurityChecks) {
		var vulnResults report.Results
		vulnResults, eosl, err = s.checkVulnerabilities(target, artifactDetail, options)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
		}
		results = append(results, vulnResults...)
	}

	// Scan IaC config files
	if utils.StringInSlice(types.SecurityCheckConfig, options.SecurityChecks) {
		iacResults, err := s.scanConfig(artifactDetail.Configs, options)
		if err != nil {
			return nil, nil, false, xerrors.Errorf("failed to scan config files: %w", err)
		}
		results = append(results, iacResults...)
	}

	return results, artifactDetail.OS, eosl, nil
}

func (s Scanner) checkVulnerabilities(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
	report.Results, bool, error) {
	var eosl bool
	var results report.Results

	if utils.StringInSlice(types.VulnTypeOS, options.VulnType) {
		result, detectedEosl, err := s.scanOSPkgs(target, detail, options)
		if err != nil {
			return nil, false, xerrors.Errorf("unable to scan OS packages: %w", err)
		} else if result != nil {
			results = append(results, *result)
		}
		eosl = detectedEosl
	}

	if utils.StringInSlice(types.VulnTypeLibrary, options.VulnType) {
		libResults, err := s.scanLibrary(detail.Applications, options)
		if err != nil {
			return nil, false, xerrors.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, libResults...)
	}

	return results, eosl, nil
}

func (s Scanner) scanOSPkgs(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
	*report.Result, bool, error) {
	if detail.OS == nil {
		log.Logger.Infof("Detected OS: unknown")
		return nil, false, nil
	}
	log.Logger.Infof("Detected OS: %s", detail.OS.Family)

	pkgs := detail.Packages
	if options.ScanRemovedPackages {
		pkgs = mergePkgs(pkgs, detail.HistoryPackages)
	}

	result, eosl, err := s.detectVulnsInOSPkgs(target, detail.OS.Family, detail.OS.Name, pkgs)
	if err != nil {
		return nil, false, xerrors.Errorf("failed to scan OS packages: %w", err)
	} else if result == nil {
		return nil, eosl, nil
	}

	if options.ListAllPackages {
		sort.Slice(pkgs, func(i, j int) bool {
			return strings.Compare(pkgs[i].Name, pkgs[j].Name) <= 0
		})
		result.Packages = pkgs
	}

	return result, eosl, nil
}

func (s Scanner) detectVulnsInOSPkgs(target, osFamily, osName string, pkgs []ftypes.Package) (*report.Result, bool, error) {
	if osFamily == "" {
		return nil, false, nil
	}
	vulns, eosl, err := s.ospkgDetector.Detect("", osFamily, osName, time.Time{}, pkgs)
	if err == ospkgDetector.ErrUnsupportedOS {
		return nil, false, nil
	} else if err != nil {
		return nil, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	artifactDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osName)
	result := &report.Result{
		Target:          artifactDetail,
		Vulnerabilities: vulns,
		Type:            osFamily,
	}
	return result, eosl, nil
}

func (s Scanner) scanLibrary(apps []ftypes.Application, options types.ScanOptions) (report.Results, error) {
	log.Logger.Infof("Number of PL dependency files: %d", len(apps))
	if len(apps) == 0 {
		return nil, nil
	}

	var results report.Results
	printedTypes := map[string]struct{}{}
	for _, app := range apps {
		if len(app.Libraries) == 0 {
			continue
		}
		if skipped(app.FilePath, options.SkipFiles, options.SkipDirectories) {
			continue
		}

		// Prevent the same log messages from being displayed many times for the same type.
		if _, ok := printedTypes[app.Type]; !ok {
			log.Logger.Infof("Detecting %s vulnerabilities...", app.Type)
			printedTypes[app.Type] = struct{}{}
		}

		log.Logger.Debugf("Detecting library vulnerabilities, type: %s, path: %s", app.Type, app.FilePath)
		vulns, err := library.Detect(app.Type, app.Libraries)
		if err != nil {
			return nil, xerrors.Errorf("failed vulnerability detection of libraries: %w", err)
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

func (s Scanner) scanConfig(configs []ftypes.Config, options types.ScanOptions) (report.Results, error) {
	log.Logger.Infof("Number of config files: %d", len(configs))

	ctx := context.TODO()
	configurations := map[string]interface{}{}
	for _, conf := range configs {
		if skipped(conf.FilePath, options.SkipFiles, options.SkipDirectories) {
			continue
		}
		log.Logger.Debugf("Scanned config file: %s", conf.FilePath)
		configurations[conf.FilePath] = conf.Content
	}

	engine, err := policy.LoadWithData(ctx, options.OPAPolicy, options.OPAData)
	if err != nil {
		return nil, xerrors.Errorf("policy load error: %w", err)
	}

	uniqResults := map[string][]types.DetectedVulnerability{}
	for _, namespace := range engine.Namespaces() {
		result, err := engine.Check(ctx, configurations, namespace)
		if err != nil {
			return nil, xerrors.Errorf("query rule: %w", err)
		}

		for _, r := range result {
			var vulns []types.DetectedVulnerability
			for _, f := range r.Failures {
				vulns = append(vulns, resultToVuln(f, dbTypes.SeverityCritical))
			}
			for _, w := range r.Warnings {
				vulns = append(vulns, resultToVuln(w, dbTypes.SeverityMedium))
			}

			uniqResults[r.FileName] = append(uniqResults[r.FileName], vulns...)
		}
	}

	var results report.Results
	for fileName, vulns := range uniqResults {
		results = append(results, report.Result{
			Target:          fileName,
			Type:            "conf", // TODO
			Vulnerabilities: vulns,
		})
	}

	return results, nil
}

func resultToVuln(res output.Result, defaultSeverity dbTypes.Severity) types.DetectedVulnerability {
	vulnerabilityID := "UNKNOWN"
	if v, ok := res.Metadata["id"]; ok {
		switch vv := v.(type) {
		case string:
			vulnerabilityID = vv
		default:
			log.Logger.Warn("id in the policy must be string (%T)", vv)
		}
	}

	checkType := "UNKNOWN"
	if v, ok := res.Metadata["type"]; ok {
		switch vv := v.(type) {
		case string:
			checkType = vv
		default:
			log.Logger.Warn("type in the policy must be string (%T)", vv)
		}
	}

	severity := defaultSeverity
	if v, ok := res.Metadata["severity"]; ok {
		switch vv := v.(type) {
		case string:
			sev, err := dbTypes.NewSeverity(vv)
			if err != nil {
				log.Logger.Warnf("severity must be %s", dbTypes.SeverityNames)
			} else {
				severity = sev
			}
		default:
			log.Logger.Warnf("id in the policy must be string (%T)", vv)
		}
	}

	return types.DetectedVulnerability{
		VulnerabilityID: vulnerabilityID,
		PkgName:         checkType, // the type is not package, but pseudo package name
		Layer:           ftypes.Layer{},
		Vulnerability: dbTypes.Vulnerability{
			Title:    res.Message,
			Severity: severity.String(),
		},
	}
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
