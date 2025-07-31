package result

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

const (
	// DefaultIgnoreFile is the file name to be evaluated
	DefaultIgnoreFile = ".trivyignore"
)

type FilterOptions struct {
	Severities         []dbTypes.Severity
	IgnoreStatuses     []dbTypes.Status
	IncludeNonFailures bool
	IgnoreFile         string
	PolicyFile         string
	IgnoreLicenses     []string
	CacheDir           string
	VEXSources         []vex.Source

	// For filtering unlikely affected packages
	IgnoreUnlikelyAffected bool
}

// Filter filters out the report
func Filter(ctx context.Context, report types.Report, opts FilterOptions) error {
	ignoreConf, err := ParseIgnoreFile(ctx, opts.IgnoreFile)
	if err != nil {
		return xerrors.Errorf("%s error: %w", opts.IgnoreFile, err)
	}

	for i := range report.Results {
		if err = FilterResult(ctx, report.ArtifactType, &report.Results[i], ignoreConf, opts); err != nil {
			return xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
	}

	// Filter out vulnerabilities based on the given VEX document.
	if err = vex.Filter(ctx, &report, vex.Options{
		CacheDir: opts.CacheDir,
		Sources:  opts.VEXSources,
	}); err != nil {
		return xerrors.Errorf("VEX error: %w", err)
	}

	return nil
}

// FilterResult filters out the result
func FilterResult(ctx context.Context, artifactType ftypes.ArtifactType, result *types.Result, ignoreConf IgnoreConfig, opt FilterOptions) error {
	// Convert dbTypes.Severity to string
	severities := lo.Map(opt.Severities, func(s dbTypes.Severity, _ int) string {
		return s.String()
	})

	filterVulnerabilities(result, artifactType, severities, opt.IgnoreStatuses, ignoreConf, opt)
	filterMisconfigurations(result, severities, opt.IncludeNonFailures, ignoreConf)
	filterSecrets(result, severities, ignoreConf)
	filterLicenses(result, severities, opt.IgnoreLicenses, ignoreConf)

	if opt.PolicyFile != "" {
		if err := applyPolicy(ctx, result, opt.PolicyFile); err != nil {
			return xerrors.Errorf("failed to apply the policy: %w", err)
		}
	}
	sort.Sort(types.BySeverity(result.Vulnerabilities))

	return nil
}

func filterVulnerabilities(result *types.Result, artifactType ftypes.ArtifactType, severities []string, ignoreStatuses []dbTypes.Status, ignoreConfig IgnoreConfig, filterOpts FilterOptions) {
	// Build a map of UID to Package for efficient lookup
	pkgByUID := lo.KeyBy(result.Packages, func(pkg ftypes.Package) string {
		return pkg.Identifier.UID
	})

	uniqVulns := make(map[string]types.DetectedVulnerability)
	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity == "" {
			vuln.Severity = dbTypes.SeverityUnknown.String()
		}

		switch {
		// Filter by severity
		case !slices.Contains(severities, vuln.Severity):
			continue
		// Filter by status
		case slices.Contains(ignoreStatuses, vuln.Status):
			continue
		}

		// Filter by ignore file
		if f := ignoreConfig.MatchVulnerability(vuln.VulnerabilityID, result.Target, vuln.PkgPath, vuln.PkgIdentifier.PURL); f != nil {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(vuln, types.FindingStatusIgnored, f.Statement, ignoreConfig.FilePath))
			continue
		}

		// Filter unlikely affected packages when --ignore-unlikely-affected is specified
		if filterOpts.IgnoreUnlikelyAffected {
			if pkg, found := pkgByUID[vuln.PkgIdentifier.UID]; found {
				if isUnlikelyAffected(pkg, artifactType) {
					result.ModifiedFindings = append(result.ModifiedFindings,
						types.NewModifiedFinding(vuln, types.FindingStatusIgnored, "Package is unlikely to be affected", "--ignore-unlikely-affected"))
					continue
				}
			}
		}

		// Check if there is a duplicate vulnerability
		key := fmt.Sprintf("%s/%s/%s/%s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, vuln.PkgPath)
		if old, ok := uniqVulns[key]; ok && !shouldOverwrite(old, vuln) {
			continue
		}
		uniqVulns[key] = vuln
	}

	// Override the detected vulnerabilities
	result.Vulnerabilities = lo.Values(uniqVulns)
	if len(result.Vulnerabilities) == 0 {
		result.Vulnerabilities = nil
	}
}

func filterMisconfigurations(result *types.Result, severities []string, includeNonFailures bool,
	ignoreConfig IgnoreConfig) {
	var filtered []types.DetectedMisconfiguration
	result.MisconfSummary = new(types.MisconfSummary)

	for _, misconf := range result.Misconfigurations {
		// Filter by severity
		if !slices.Contains(severities, misconf.Severity) {
			continue
		}

		// Filter by ignore file
		if f := ignoreConfig.MatchMisconfiguration(misconf.ID, misconf.AVDID, result.Target); f != nil {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(misconf, types.FindingStatusIgnored, f.Statement, ignoreConfig.FilePath))
			continue
		}

		// Count successes and failures
		summarize(misconf.Status, result.MisconfSummary)

		if misconf.Status != types.MisconfStatusFailure && !includeNonFailures {
			continue
		}
		filtered = append(filtered, misconf)
	}

	result.Misconfigurations = filtered
	if result.MisconfSummary.Empty() {
		result.Misconfigurations = nil
		result.MisconfSummary = nil
	}
}

func filterSecrets(result *types.Result, severities []string, ignoreConfig IgnoreConfig) {
	var filtered []types.DetectedSecret
	for _, secret := range result.Secrets {
		if !slices.Contains(severities, secret.Severity) {
			// Filter by severity
			continue
		} else if f := ignoreConfig.MatchSecret(secret.RuleID, result.Target); f != nil {
			// Filter by ignore file
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(secret, types.FindingStatusIgnored, f.Statement, ignoreConfig.FilePath))
			continue
		}
		filtered = append(filtered, secret)
	}
	result.Secrets = filtered
}

func filterLicenses(result *types.Result, severities, ignoreLicenseNames []string, ignoreConfig IgnoreConfig) {
	// Merge ignore license names into ignored findings
	var ignoreLicenses IgnoreConfig
	for _, licenseName := range ignoreLicenseNames {
		ignoreLicenses.Licenses = append(ignoreLicenses.Licenses, IgnoreFinding{
			ID: licenseName,
		})
	}

	var filtered []types.DetectedLicense
	for _, l := range result.Licenses {
		// Filter by severity
		if !slices.Contains(severities, l.Severity) {
			continue
		}

		// Filter by `--ignored-licenses`
		if f := ignoreLicenses.MatchLicense(l.Name, l.FilePath); f != nil {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(l, types.FindingStatusIgnored, "", "--ignored-licenses"))
			continue
		}

		// Filter by ignore file
		if f := ignoreConfig.MatchLicense(l.Name, l.FilePath); f != nil {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(l, types.FindingStatusIgnored, f.Statement, ignoreConfig.FilePath))
			continue
		}

		filtered = append(filtered, l)
	}
	result.Licenses = filtered
}

func summarize(status types.MisconfStatus, summary *types.MisconfSummary) {
	switch status {
	case types.MisconfStatusFailure:
		summary.Failures++
	case types.MisconfStatusPassed:
		summary.Successes++
	}
}

func applyPolicy(ctx context.Context, result *types.Result, policyFile string) error {
	policy, err := os.ReadFile(policyFile)
	if err != nil {
		return xerrors.Errorf("unable to read the policy file: %w", err)
	}

	query, err := rego.New(
		rego.Query("data.trivy.ignore"),
		rego.Module("lib.rego", module),
		rego.Module("trivy.rego", string(policy)),
		rego.SetRegoVersion(ast.RegoV0),
	).PrepareForEval(ctx)
	if err != nil {
		return xerrors.Errorf("unable to prepare for eval: %w", err)
	}

	policyFile = filepath.ToSlash(filepath.Clean(policyFile))

	// Vulnerabilities
	var filteredVulns []types.DetectedVulnerability
	for _, vuln := range result.Vulnerabilities {
		ignored, err := evaluate(ctx, query, vuln)
		if err != nil {
			return err
		}
		if ignored {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(vuln, types.FindingStatusIgnored, "Filtered by Rego", policyFile))
			continue
		}
		filteredVulns = append(filteredVulns, vuln)
	}
	result.Vulnerabilities = filteredVulns

	// Misconfigurations
	var filteredMisconfs []types.DetectedMisconfiguration
	for _, misconf := range result.Misconfigurations {
		ignored, err := evaluate(ctx, query, misconf)
		if err != nil {
			return err
		}
		if ignored {
			switch misconf.Status {
			case types.MisconfStatusFailure:
				result.MisconfSummary.Failures--
			case types.MisconfStatusPassed:
				result.MisconfSummary.Successes--
			}
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(misconf, types.FindingStatusIgnored, "Filtered by Rego", policyFile))
			continue
		}
		filteredMisconfs = append(filteredMisconfs, misconf)
	}
	result.Misconfigurations = filteredMisconfs

	// Secrets
	var filteredSecrets []types.DetectedSecret
	for _, scrt := range result.Secrets {
		ignored, err := evaluate(ctx, query, scrt)
		if err != nil {
			return err
		}
		if ignored {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(scrt, types.FindingStatusIgnored, "Filtered by Rego", policyFile))
			continue
		}
		filteredSecrets = append(filteredSecrets, scrt)
	}
	result.Secrets = filteredSecrets

	// Licenses
	var filteredLicenses []types.DetectedLicense
	for _, lic := range result.Licenses {
		ignored, err := evaluate(ctx, query, lic)
		if err != nil {
			return err
		}
		if ignored {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(lic, types.FindingStatusIgnored, "Filtered by Rego", policyFile))
			continue
		}
		filteredLicenses = append(filteredLicenses, lic)
	}
	result.Licenses = filteredLicenses

	return nil
}

func evaluate(ctx context.Context, query rego.PreparedEvalQuery, input any) (bool, error) {
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, xerrors.Errorf("unable to evaluate the policy: %w", err)
	} else if len(results) == 0 {
		// Handle undefined result.
		return false, nil
	}
	ignore, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		// Handle unexpected result type.
		return false, xerrors.New("the policy must return boolean")
	}
	return ignore, nil
}

func shouldOverwrite(oldVuln, newVuln types.DetectedVulnerability) bool {
	// The same vulnerability must be picked always.
	return oldVuln.FixedVersion < newVuln.FixedVersion
}

// isUnlikelyAffected checks if a package is unlikely to affect the artifact
func isUnlikelyAffected(pkg ftypes.Package, artifactType ftypes.ArtifactType) bool {
	// Filter kernel packages only for container images
	if artifactType == ftypes.TypeContainerImage && isKernelPackage(pkg) {
		return true
	}

	// Filter documentation, license, and debug packages regardless of artifact type
	if isDocumentationPackage(pkg.Name) {
		return true
	}

	return false
}

// isKernelPackage checks if a package is a kernel package across different distributions
func isKernelPackage(pkg ftypes.Package) bool {
	// Debian/Ubuntu/Alpine and others: source name "linux" or "linux-*"
	if pkg.SrcName == "linux" || strings.HasPrefix(pkg.SrcName, "linux-") {
		return true
	}

	// Red Hat/CentOS/RHEL/Alma/Rocky/Fedora/SUSE/Amazon Linux: source name starting with "kernel"
	if strings.HasPrefix(pkg.SrcName, "kernel") {
		return true
	}

	return false
}

// isDocumentationPackage checks if a package is a documentation, license, or debug package
func isDocumentationPackage(pkgName string) bool {
	unlikelyPatterns := []string{
		"-doc",
		"-docs",
		"-license",
		"-dbg",
		"-debug",
	}

	for _, pattern := range unlikelyPatterns {
		if strings.HasSuffix(pkgName, pattern) {
			return true
		}
	}

	return false
}
