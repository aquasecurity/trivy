package local

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/scanner/post"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/all"
)

// SuperSet binds dependencies for Local scan
var SuperSet = wire.NewSet(
	vulnerability.SuperSet,
	applier.NewApplier,
	ospkg.NewScanner,
	langpkg.NewScanner,
	NewScanner,
)

// Scanner implements the OspkgDetector and LibraryDetector
type Scanner struct {
	applier        applier.Applier
	osPkgScanner   ospkg.Scanner
	langPkgScanner langpkg.Scanner
	vulnClient     vulnerability.Client
}

// NewScanner is the factory method for Scanner
func NewScanner(a applier.Applier, osPkgScanner ospkg.Scanner, langPkgScanner langpkg.Scanner,
	vulnClient vulnerability.Client) Scanner {
	return Scanner{
		applier:        a,
		osPkgScanner:   osPkgScanner,
		langPkgScanner: langPkgScanner,
		vulnClient:     vulnClient,
	}
}

// Scan scans the artifact and return results.
func (s Scanner) Scan(ctx context.Context, targetName, artifactKey string, blobKeys []string, options types.ScanOptions) (
	types.Results, ftypes.OS, error) {
	detail, err := s.applier.ApplyLayers(artifactKey, blobKeys)
	switch {
	case errors.Is(err, analyzer.ErrUnknownOS):
		log.Debug("OS is not detected.")

		// Packages may contain OS-independent binary information even though OS is not detected.
		if len(detail.Packages) != 0 {
			detail.OS = ftypes.OS{Family: "none"}
		}

		// If OS is not detected and repositories are detected, we'll try to use repositories as OS.
		if detail.Repository != nil {
			log.Debug("Package repository", log.String("family", string(detail.Repository.Family)),
				log.String("version", detail.Repository.Release))
			log.Debug("Assuming OS", log.String("family", string(detail.Repository.Family)),
				log.String("version", detail.Repository.Release))
			detail.OS = ftypes.OS{
				Family: detail.Repository.Family,
				Name:   detail.Repository.Release,
			}
		}
	case errors.Is(err, analyzer.ErrNoPkgsDetected):
		log.Warn("No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.")
		log.Warn(`e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"`)
	case err != nil:
		return nil, ftypes.OS{}, xerrors.Errorf("failed to apply layers: %w", err)
	}

	target := types.ScanTarget{
		Name:              targetName,
		OS:                detail.OS,
		Repository:        detail.Repository,
		Packages:          mergePkgs(detail.Packages, detail.ImageConfig.Packages, options),
		Applications:      detail.Applications,
		Misconfigurations: mergeMisconfigurations(targetName, detail),
		Secrets:           mergeSecrets(targetName, detail),
		Licenses:          detail.Licenses,
		CustomResources:   detail.CustomResources,
	}

	return s.ScanTarget(ctx, target, options)
}

func (s Scanner) ScanTarget(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Results, ftypes.OS, error) {
	var results types.Results

	// By default, we need to remove dev dependencies from the result
	// IncludeDevDeps option allows you not to remove them
	excludeDevDeps(target.Applications, options.IncludeDevDeps)

	// Add packages if needed and scan packages for vulnerabilities
	vulnResults, eosl, err := s.scanVulnerabilities(ctx, target, options)
	if err != nil {
		return nil, ftypes.OS{}, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
	}
	target.OS.Eosl = eosl
	results = append(results, vulnResults...)

	// Store misconfigurations
	results = append(results, s.misconfsToResults(target.Misconfigurations, options)...)

	// Store secrets
	results = append(results, s.secretsToResults(target.Secrets, options)...)

	// Scan licenses
	results = append(results, s.scanLicenses(target, options)...)

	// For WASM plugins and custom analyzers
	if len(target.CustomResources) != 0 {
		results = append(results, types.Result{
			Class:           types.ClassCustom,
			CustomResources: target.CustomResources,
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

	return results, target.OS, nil
}

func (s Scanner) scanVulnerabilities(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (
	types.Results, bool, error) {
	if !options.Scanners.AnyEnabled(types.SBOMScanner, types.VulnerabilityScanner) {
		return nil, false, nil
	}

	var eosl bool
	var results types.Results

	if slices.Contains(options.VulnType, types.VulnTypeOS) {
		vuln, detectedEOSL, err := s.osPkgScanner.Scan(ctx, target, options)
		switch {
		case errors.Is(err, ospkgDetector.ErrUnsupportedOS):
		// do nothing
		case err != nil:
			return nil, false, xerrors.Errorf("unable to scan OS packages: %w", err)
		case vuln.Target != "":
			results = append(results, vuln)
			eosl = detectedEOSL
		}
	}

	if slices.Contains(options.VulnType, types.VulnTypeLibrary) {
		vulns, err := s.langPkgScanner.Scan(ctx, target, options)
		if err != nil {
			return nil, false, xerrors.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, vulns...)
	}

	return results, eosl, nil
}

func (s Scanner) misconfsToResults(misconfs []ftypes.Misconfiguration, options types.ScanOptions) types.Results {
	if !ShouldScanMisconfigOrRbac(options.Scanners) &&
		!options.ImageConfigScanners.Enabled(types.MisconfigScanner) {
		return nil
	}

	return s.MisconfsToResults(misconfs)
}

// MisconfsToResults is exported for trivy-plugin-aqua purposes only
func (s Scanner) MisconfsToResults(misconfs []ftypes.Misconfiguration) types.Results {
	log.Info("Detected config files", log.Int("num", len(misconfs)))
	var results types.Results
	for _, misconf := range misconfs {
		log.Debug("Scanned config file", log.FilePath(misconf.FilePath))

		var detected []types.DetectedMisconfiguration

		for _, f := range misconf.Failures {
			detected = append(detected, toDetectedMisconfiguration(f, dbTypes.SeverityCritical, types.MisconfStatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Warnings {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityMedium, types.MisconfStatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Successes {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.MisconfStatusPassed, misconf.Layer))
		}
		for _, w := range misconf.Exceptions {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.MisconfStatusException, misconf.Layer))
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

func (s Scanner) secretsToResults(secrets []ftypes.Secret, options types.ScanOptions) types.Results {
	if !options.Scanners.Enabled(types.SecretScanner) {
		return nil
	}

	var results types.Results
	for _, secret := range secrets {
		log.Debug("Secret file", log.FilePath(secret.FilePath))

		results = append(results, types.Result{
			Target: secret.FilePath,
			Class:  types.ClassSecret,
			Secrets: lo.Map(secret.Findings, func(secret ftypes.SecretFinding, index int) types.DetectedSecret {
				return types.DetectedSecret(secret)
			}),
		})
	}
	return results
}

func (s Scanner) scanLicenses(target types.ScanTarget, options types.ScanOptions) types.Results {
	if !options.Scanners.Enabled(types.LicenseScanner) {
		return nil
	}

	var results types.Results
	scanner := licensing.NewScanner(options.LicenseCategories)

	// License - OS packages
	var osPkgLicenses []types.DetectedLicense
	for _, pkg := range target.Packages {
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
	for _, app := range target.Applications {
		var langLicenses []types.DetectedLicense
		for _, lib := range app.Packages {
			for _, license := range lib.Licenses {
				category, severity := scanner.Scan(license)
				langLicenses = append(langLicenses, types.DetectedLicense{
					Severity: severity,
					Category: category,
					PkgName:  lib.Name,
					Name:     license,
					// Lock files use app.FilePath - https://github.com/aquasecurity/trivy/blob/6ccc0a554b07b05fd049f882a1825a0e1e0aabe1/pkg/fanal/types/artifact.go#L245-L246
					// Applications use lib.FilePath - https://github.com/aquasecurity/trivy/blob/6ccc0a554b07b05fd049f882a1825a0e1e0aabe1/pkg/fanal/types/artifact.go#L93-L94
					FilePath:   lo.Ternary(lib.FilePath != "", lib.FilePath, app.FilePath),
					Confidence: 1.0,
				})
			}
		}

		targetName := app.FilePath
		if t, ok := langpkg.PkgTargets[app.Type]; ok && targetName == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			targetName = t
		}
		results = append(results, types.Result{
			Target:   targetName,
			Class:    types.ClassLicense,
			Licenses: langLicenses,
		})
	}

	// License - file header or license file
	var fileLicenses []types.DetectedLicense
	for _, license := range target.Licenses {
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
		log.Warn("Unsupported severity", log.String("severity", res.Severity))
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
	if res.Namespace == "" || rego.IsBuiltinNamespace(res.Namespace) {
		primaryURL = fmt.Sprintf("https://avd.aquasec.com/misconfig/%s", strings.ToLower(res.ID))
		res.References = append(res.References, primaryURL)
	}

	if primaryURL == "" && len(res.References) > 0 {
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
			Resource:    res.Resource,
			Provider:    res.Provider,
			Service:     res.Service,
			StartLine:   res.StartLine,
			EndLine:     res.EndLine,
			Code:        res.Code,
			Occurrences: res.Occurrences,
		},
	}
}

func ShouldScanMisconfigOrRbac(scanners types.Scanners) bool {
	return scanners.AnyEnabled(types.MisconfigScanner, types.RBACScanner)
}

// excludeDevDeps removes development dependencies from the list of applications
func excludeDevDeps(apps []ftypes.Application, include bool) {
	if include {
		return
	}

	onceInfo := sync.OnceFunc(func() {
		log.Info("Suppressing dependencies for development and testing. To display them, try the '--include-dev-deps' flag.")
	})
	for i := range apps {
		apps[i].Packages = lo.Filter(apps[i].Packages, func(lib ftypes.Package, index int) bool {
			if lib.Dev {
				onceInfo()
			}
			return !lib.Dev
		})
	}
}

func mergePkgs(pkgs, pkgsFromCommands []ftypes.Package, options types.ScanOptions) []ftypes.Package {
	if !options.ScanRemovedPackages || len(pkgsFromCommands) == 0 {
		return pkgs
	}

	// pkg has priority over pkgsFromCommands
	uniqPkgs := make(map[string]struct{})
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

// mergeMisconfigurations merges misconfigurations on container image config
func mergeMisconfigurations(targetName string, detail ftypes.ArtifactDetail) []ftypes.Misconfiguration {
	if detail.ImageConfig.Misconfiguration == nil {
		return detail.Misconfigurations
	}

	// Append misconfigurations on container image config
	misconf := detail.ImageConfig.Misconfiguration
	misconf.FilePath = targetName // Set the target name to the file path as container image config is not a real file.
	return append(detail.Misconfigurations, *misconf)
}

// mergeSecrets merges secrets on container image config.
func mergeSecrets(targetName string, detail ftypes.ArtifactDetail) []ftypes.Secret {
	if detail.ImageConfig.Secret == nil {
		return detail.Secrets
	}

	// Append secrets on container image config
	secret := detail.ImageConfig.Secret
	secret.FilePath = targetName // Set the target name to the file path as container image config is not a real file.
	return append(detail.Secrets, *secret)
}
