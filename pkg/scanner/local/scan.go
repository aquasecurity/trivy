package local

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/all"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/all"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/post"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

var (
	pkgTargets = map[string]string{
		ftypes.PythonPkg: "Python",
		ftypes.CondaPkg:  "Conda",
		ftypes.GemSpec:   "Ruby",
		ftypes.NodePkg:   "Node.js",
		ftypes.Jar:       "Java",
	}
)

// SuperSet binds dependencies for Local scan
var SuperSet = wire.NewSet(
	vulnerability.SuperSet,
	applier.NewApplier,
	wire.Bind(new(Applier), new(applier.Applier)),
	wire.Struct(new(ospkgDetector.Detector)),
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
	vulnClient    vulnerability.Client
}

// NewScanner is the factory method for Scanner
func NewScanner(applier Applier, ospkgDetector OspkgDetector, vulnClient vulnerability.Client) Scanner {
	return Scanner{
		applier:       applier,
		ospkgDetector: ospkgDetector,
		vulnClient:    vulnClient,
	}
}

// Scan scans the artifact and return results.
func (s Scanner) Scan(ctx context.Context, target, artifactKey string, blobKeys []string, options types.ScanOptions) (types.Results, ftypes.OS, error) {
	artifactDetail, err := s.applier.ApplyLayers(artifactKey, blobKeys)
	switch {
	case errors.Is(err, analyzer.ErrUnknownOS):
		log.Logger.Debug("OS is not detected.")

		// Packages may contain OS-independent binary information even though OS is not detected.
		if len(artifactDetail.Packages) != 0 {
			artifactDetail.OS = ftypes.OS{Family: "none"}
		}

		// If OS is not detected and repositories are detected, we'll try to use repositories as OS.
		if artifactDetail.Repository != nil {
			log.Logger.Debugf("Package repository: %s %s", artifactDetail.Repository.Family, artifactDetail.Repository.Release)
			log.Logger.Debugf("Assuming OS is %s %s.", artifactDetail.Repository.Family, artifactDetail.Repository.Release)
			artifactDetail.OS = ftypes.OS{
				Family: artifactDetail.Repository.Family,
				Name:   artifactDetail.Repository.Release,
			}
		}
	case errors.Is(err, analyzer.ErrNoPkgsDetected):
		log.Logger.Warn("No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.")
		log.Logger.Warn(`e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"`)
	case err != nil:
		return nil, ftypes.OS{}, xerrors.Errorf("failed to apply layers: %w", err)
	}

	var eosl bool
	var results, pkgResults types.Results

	// Fill OS packages and language-specific packages
	if options.ListAllPackages {
		if res := s.osPkgsToResult(target, artifactDetail, options); res != nil {
			pkgResults = append(pkgResults, *res)
		}
		pkgResults = append(pkgResults, s.langPkgsToResult(artifactDetail)...)
	}

	// Scan packages for vulnerabilities
	if options.Scanners.Enabled(types.VulnerabilityScanner) {
		var vulnResults types.Results
		vulnResults, eosl, err = s.scanVulnerabilities(target, artifactDetail, options)
		if err != nil {
			return nil, ftypes.OS{}, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
		}
		artifactDetail.OS.Eosl = eosl

		// Merge package results into vulnerability results
		mergedResults := s.fillPkgsInVulns(pkgResults, vulnResults)

		results = append(results, mergedResults...)
	} else {
		// If vulnerability scanning is not enabled, it just adds package results.
		results = append(results, pkgResults...)
	}

	// Scan IaC config files
	if ShouldScanMisconfigOrRbac(options.Scanners) {
		configResults := s.MisconfsToResults(artifactDetail.Misconfigurations)
		results = append(results, configResults...)
	}

	// Scan secrets
	if options.Scanners.Enabled(types.SecretScanner) {
		secretResults := s.secretsToResults(artifactDetail.Secrets)
		results = append(results, secretResults...)
	}

	// Scan licenses
	if options.Scanners.Enabled(types.LicenseScanner) {
		licenseResults := s.scanLicenses(artifactDetail, options.LicenseCategories)
		results = append(results, licenseResults...)
	}

	// Scan misconfigurations on container image config
	if options.ImageConfigScanners.Enabled(types.MisconfigScanner) {
		if im := artifactDetail.ImageConfig.Misconfiguration; im != nil {
			im.FilePath = target // Set the target name to the file path as container image config is not a real file.
			results = append(results, s.MisconfsToResults([]ftypes.Misconfiguration{*im})...)
		}
	}

	// Scan secrets on container image config
	if options.ImageConfigScanners.Enabled(types.SecretScanner) {
		if is := artifactDetail.ImageConfig.Secret; is != nil {
			is.FilePath = target // Set the target name to the file path as container image config is not a real file.
			results = append(results, s.secretsToResults([]ftypes.Secret{*is})...)
		}
	}

	// For WASM plugins and custom analyzers
	if len(artifactDetail.CustomResources) != 0 {
		results = append(results, types.Result{
			Class:           types.ClassCustom,
			CustomResources: artifactDetail.CustomResources,
		})
	}

	for i := range results {
		// Fill vulnerability details
		s.vulnClient.FillInfo(results[i].Vulnerabilities)
	}

	// Post scanning
	results, err = post.Scan(ctx, results)
	if err != nil {
		return nil, ftypes.OS{}, xerrors.Errorf("post scan error: %w", err)
	}

	return results, artifactDetail.OS, nil
}

func (s Scanner) osPkgsToResult(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) *types.Result {
	if len(detail.Packages) == 0 || !detail.OS.Detected() {
		return nil
	}

	pkgs := detail.Packages
	if options.ScanRemovedPackages {
		pkgs = mergePkgs(pkgs, detail.ImageConfig.Packages)
	}
	sort.Sort(pkgs)
	return &types.Result{
		Target:   fmt.Sprintf("%s (%s %s)", target, detail.OS.Family, detail.OS.Name),
		Class:    types.ClassOSPkg,
		Type:     detail.OS.Family,
		Packages: pkgs,
	}
}

func (s Scanner) langPkgsToResult(detail ftypes.ArtifactDetail) types.Results {
	var results types.Results
	for _, app := range detail.Applications {
		if len(app.Libraries) == 0 {
			continue
		}
		target := app.FilePath
		if t, ok := pkgTargets[app.Type]; ok && target == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			target = t
		}

		results = append(results, types.Result{
			Target:   target,
			Class:    types.ClassLangPkg,
			Type:     app.Type,
			Packages: app.Libraries,
		})
	}
	return results
}

func (s Scanner) scanVulnerabilities(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
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
		libResults, err := s.scanLangPkgs(detail.Applications)
		if err != nil {
			return nil, false, xerrors.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, libResults...)
	}

	return results, eosl, nil
}

func (s Scanner) scanOSPkgs(target string, detail ftypes.ArtifactDetail, options types.ScanOptions) (
	*types.Result, bool, error) {
	if !detail.OS.Detected() {
		log.Logger.Debug("Detected OS: unknown")
		return nil, false, nil
	}
	log.Logger.Infof("Detected OS: %s", detail.OS.Family)

	pkgs := detail.Packages
	if options.ScanRemovedPackages {
		pkgs = mergePkgs(pkgs, detail.ImageConfig.Packages)
	}

	if detail.OS.Extended {
		// TODO: move the logic to each detector
		detail.OS.Name += "-ESM"
	}

	vulns, eosl, err := s.ospkgDetector.Detect("", detail.OS.Family, detail.OS.Name, detail.Repository, time.Time{}, pkgs)
	if err == ospkgDetector.ErrUnsupportedOS {
		return nil, false, nil
	} else if err != nil {
		return nil, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	artifactDetail := fmt.Sprintf("%s (%s %s)", target, detail.OS.Family, detail.OS.Name)
	result := &types.Result{
		Target:          artifactDetail,
		Vulnerabilities: vulns,
		Class:           types.ClassOSPkg,
		Type:            detail.OS.Family,
	}
	return result, eosl, nil
}

func (s Scanner) scanLangPkgs(apps []ftypes.Application) (types.Results, error) {
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
		} else if len(vulns) == 0 {
			continue
		}

		target := app.FilePath
		if t, ok := pkgTargets[app.Type]; ok && target == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			target = t
		}

		results = append(results, types.Result{
			Target:          target,
			Vulnerabilities: vulns,
			Class:           types.ClassLangPkg,
			Type:            app.Type,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}

func (s Scanner) fillPkgsInVulns(pkgResults, vulnResults types.Results) types.Results {
	var results types.Results
	if len(pkgResults) == 0 { // '--list-all-pkgs' == false or packages not found
		return vulnResults
	}
	for _, result := range pkgResults {
		if r, found := lo.Find(vulnResults, func(r types.Result) bool {
			return r.Class == result.Class && r.Target == result.Target
		}); found {
			r.Packages = result.Packages
			results = append(results, r)
		} else { // when package result has no vulnerabilities we still need to add it to result(for 'list-all-pkgs')
			results = append(results, result)
		}
	}
	return results
}

// This function is exported for trivy-plugin-aqua purposes only
func (s Scanner) MisconfsToResults(misconfs []ftypes.Misconfiguration) types.Results {
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

func (s Scanner) scanLicenses(detail ftypes.ArtifactDetail,
	categories map[ftypes.LicenseCategory][]string) types.Results {
	scanner := licensing.NewScanner(categories)

	var results types.Results

	// License - OS packages
	var osPkgLicenses []types.DetectedLicense
	for _, pkg := range detail.Packages {
		for _, license := range pkg.Licenses {
			category, severity := scanner.Scan(license)
			osPkgLicenses = append(osPkgLicenses, types.DetectedLicense{
				Severity:   severity,
				Category:   category,
				PkgName:    pkg.Name,
				Name:       license,
				Confidence: 1.0,
			})
		}

	}
	results = append(results, types.Result{
		Target:   "OS Packages",
		Class:    types.ClassLicense,
		Licenses: osPkgLicenses,
	})

	// License - language-specific packages
	for _, app := range detail.Applications {
		var langLicenses []types.DetectedLicense
		for _, lib := range app.Libraries {
			for _, license := range lib.Licenses {
				category, severity := scanner.Scan(license)
				langLicenses = append(langLicenses, types.DetectedLicense{
					Severity:   severity,
					Category:   category,
					PkgName:    lib.Name,
					Name:       license,
					Confidence: 1.0,
				})
			}
		}

		target := app.FilePath
		if t, ok := pkgTargets[app.Type]; ok && target == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			target = t
		}
		results = append(results, types.Result{
			Target:   target,
			Class:    types.ClassLicense,
			Licenses: langLicenses,
		})
	}

	// License - file header or license file
	var fileLicenses []types.DetectedLicense
	for _, license := range detail.Licenses {
		for _, finding := range license.Findings {
			category, severity := scanner.Scan(finding.Name)
			fileLicenses = append(fileLicenses, types.DetectedLicense{
				Severity:   severity,
				Category:   category,
				FilePath:   license.FilePath,
				Name:       finding.Name,
				Confidence: finding.Confidence,
				Link:       finding.Link,
			})

		}
	}
	results = append(results, types.Result{
		Target:   "Loose File License(s)",
		Class:    types.ClassLicenseFile,
		Licenses: fileLicenses,
	})

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

	if len(primaryURL) == 0 && len(res.References) > 0 {
		primaryURL = res.References[0]
	}

	return types.DetectedMisconfiguration{
		ID:          res.ID,
		AVDID:       res.AVDID,
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

func ShouldScanMisconfigOrRbac(scanners types.Scanners) bool {
	return scanners.AnyEnabled(types.MisconfigScanner, types.RBACScanner)
}
