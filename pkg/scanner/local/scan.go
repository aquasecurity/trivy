package local

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/wire"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/applier"
	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "github.com/aquasecurity/fanal/analyzer/all"
	_ "github.com/aquasecurity/fanal/handler/all"
)

var (
	pkgTargets = map[string]string{
		ftypes.PythonPkg: "Python",
		ftypes.GemSpec:   "Ruby",
		ftypes.NodePkg:   "Node.js",
		ftypes.Jar:       "Java",
	}
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
	Detect(imageName, osFamily, osName string, repo *ftypes.Repository, created time.Time, pkgs []ftypes.Package) (detectedVulns []types.DetectedVulnerability, eosl bool, err error)
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
func (s Scanner) Scan(target string, artifactKey string, blobKeys []string, options types.ScanOptions) (types.Results, *ftypes.OS, error) {
	artifactDetail, err := s.applier.ApplyLayers(artifactKey, blobKeys)
	switch {
	case errors.Is(err, analyzer.ErrUnknownOS):
		log.Logger.Debug("OS is not detected.")

		// If OS is not detected and repositories are detected, we'll try to use repositories as OS.
		if artifactDetail.Repository != nil {
			log.Logger.Debugf("Package repository: %s %s", artifactDetail.Repository.Family, artifactDetail.Repository.Release)
			log.Logger.Debugf("Assuming OS is %s %s.", artifactDetail.Repository.Family, artifactDetail.Repository.Release)
			artifactDetail.OS = &ftypes.OS{
				Family: artifactDetail.Repository.Family,
				Name:   artifactDetail.Repository.Release,
			}
		}
	case errors.Is(err, analyzer.ErrNoPkgsDetected):
		log.Logger.Warn("No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.")
		log.Logger.Warn(`e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"`)
	case err != nil:
		return nil, nil, xerrors.Errorf("failed to apply layers: %w", err)
	}

	var eosl bool
	var results types.Results

	// Scan OS packages and language-specific dependencies
	if slices.Contains(options.SecurityChecks, types.SecurityCheckVulnerability) {
		var vulnResults types.Results
		vulnResults, eosl, err = s.checkVulnerabilities(target, artifactDetail, options)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
		}
		if artifactDetail.OS != nil {
			artifactDetail.OS.Eosl = eosl
		}
		results = append(results, vulnResults...)
	}

	// Scan IaC config files
	if slices.Contains(options.SecurityChecks, types.SecurityCheckConfig) {
		configResults := s.misconfsToResults(artifactDetail.Misconfigurations)
		results = append(results, configResults...)
	}

	// Scan secrets
	if slices.Contains(options.SecurityChecks, types.SecurityCheckSecret) {
		secretResults := s.secretsToResults(artifactDetail.Secrets)
		results = append(results, secretResults...)
	}

	return results, artifactDetail.OS, nil
}

func (s Scanner) checkVulnerabilities(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
	types.Results, bool, error) {
	var eosl bool
	var results types.Results

	if slices.Contains(options.VulnType, types.VulnTypeOS) {
		result, detectedEosl, err := s.scanOSPkgs(target, detail, options)
		if err != nil {
			return nil, false, xerrors.Errorf("unable to scan OS packages: %w", err)
		} else if result != nil {
			results = append(results, *result)
		}
		eosl = detectedEosl
	}

	if slices.Contains(options.VulnType, types.VulnTypeLibrary) {
		libResults, err := s.scanLibrary(detail.Applications, options)
		if err != nil {
			return nil, false, xerrors.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, libResults...)
	}

	return results, eosl, nil
}

func (s Scanner) scanOSPkgs(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
	*types.Result, bool, error) {
	if detail.OS == nil {
		log.Logger.Debug("Detected OS: unknown")
		return nil, false, nil
	}
	log.Logger.Infof("Detected OS: %s", detail.OS.Family)

	pkgs := detail.Packages
	if options.ScanRemovedPackages {
		pkgs = mergePkgs(pkgs, detail.HistoryPackages)
	}

	result, eosl, err := s.detectVulnsInOSPkgs(target, detail.OS.Family, detail.OS.Name, detail.Repository, pkgs)
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

func (s Scanner) detectVulnsInOSPkgs(target, osFamily, osName string, repo *ftypes.Repository, pkgs []ftypes.Package) (*types.Result, bool, error) {
	if osFamily == "" {
		return nil, false, nil
	}
	vulns, eosl, err := s.ospkgDetector.Detect("", osFamily, osName, repo, time.Time{}, pkgs)
	if err == ospkgDetector.ErrUnsupportedOS {
		return nil, false, nil
	} else if err != nil {
		return nil, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	artifactDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osName)
	result := &types.Result{
		Target:          artifactDetail,
		Vulnerabilities: vulns,
		Class:           types.ClassOSPkg,
		Type:            osFamily,
	}
	return result, eosl, nil
}

func (s Scanner) scanLibrary(apps []ftypes.Application, options types.ScanOptions) (types.Results, error) {
	log.Logger.Infof("Number of language-specific files: %d", len(apps))
	if len(apps) == 0 {
		return nil, nil
	}

	var results types.Results
	printedTypes := map[string]struct{}{}
	for _, app := range apps {
		if len(app.Libraries) == 0 {
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

		target := app.FilePath
		if t, ok := pkgTargets[app.Type]; ok && target == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			target = t
		}

		libReport := types.Result{
			Target:          target,
			Vulnerabilities: vulns,
			Class:           types.ClassLangPkg,
			Type:            app.Type,
		}
		if options.ListAllPackages {
			libReport.Packages = app.Libraries
		}
		results = append(results, libReport)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}

func (s Scanner) misconfsToResults(misconfs []ftypes.Misconfiguration) types.Results {
	log.Logger.Infof("Detected config files: %d", len(misconfs))
	var results types.Results
	for _, misconf := range misconfs {
		log.Logger.Debugf("Scanned config file: %s", misconf.FilePath)

		var detected []types.DetectedMisconfiguration

		for _, f := range misconf.Failures {
			detected = append(detected, toDetectedMisconfiguration(f, dbTypes.SeverityCritical, types.StatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Warnings {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityMedium, types.StatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Successes {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.StatusPassed, misconf.Layer))
		}
		for _, w := range misconf.Exceptions {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.StatusException, misconf.Layer))
		}

		results = append(results, types.Result{
			Target:            misconf.FilePath,
			Class:             types.ClassConfig,
			Type:              misconf.FileType,
			Misconfigurations: detected,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})

	return results
}

func (s Scanner) secretsToResults(secrets []ftypes.Secret) types.Results {
	var results types.Results
	for _, secret := range secrets {
		log.Logger.Debugf("Secret file: %s", secret.FilePath)

		results = append(results, types.Result{
			Target:  secret.FilePath,
			Class:   types.ClassSecret,
			Secrets: secret.Findings,
		})
	}
	return results
}

func toDetectedMisconfiguration(res ftypes.MisconfResult, defaultSeverity dbTypes.Severity,
	status types.MisconfStatus, layer ftypes.Layer) types.DetectedMisconfiguration {

	severity := defaultSeverity
	sev, err := dbTypes.NewSeverity(res.Severity)
	if err != nil {
		log.Logger.Warnf("severity must be %s, but %s", dbTypes.SeverityNames, res.Severity)
	} else {
		severity = sev
	}

	msg := strings.TrimSpace(res.Message)
	if msg == "" {
		msg = "No issues found"
	}

	var primaryURL string

	// empty namespace implies a go rule from defsec, "builtin" refers to a built-in rego rule
	// this ensures we don't generate bad links for custom policies
	if res.Namespace == "" || strings.HasPrefix(res.Namespace, "builtin.") {
		primaryURL = fmt.Sprintf("https://avd.aquasec.com/misconfig/%s", strings.ToLower(res.ID))
		res.References = append(res.References, primaryURL)
	}

	return types.DetectedMisconfiguration{
		ID:          res.ID,
		Type:        res.Type,
		Title:       res.Title,
		Description: res.Description,
		Message:     msg,
		Resolution:  res.RecommendedActions,
		Namespace:   res.Namespace,
		Query:       res.Query,
		Severity:    severity.String(),
		PrimaryURL:  primaryURL,
		References:  res.References,
		Status:      status,
		Layer:       layer,
		Traces:      res.Traces,
		CauseMetadata: ftypes.CauseMetadata{
			Resource:  res.Resource,
			Provider:  res.Provider,
			Service:   res.Service,
			StartLine: res.StartLine,
			EndLine:   res.EndLine,
			Code:      res.Code,
		},
	}
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
