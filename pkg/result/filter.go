package result

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/open-policy-agent/opa/rego"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

const (
	// DefaultIgnoreFile is the file name to be evaluated
	DefaultIgnoreFile = ".trivyignore"
)

type FilterOption struct {
	Severities         []dbTypes.Severity
	IgnoreStatuses     []dbTypes.Status
	IncludeNonFailures bool
	IgnoreFile         string
	PolicyFile         string
	IgnoreLicenses     []string
	VEXPath            string
}

// Filter filters out the report
func Filter(ctx context.Context, report types.Report, opt FilterOption) error {
	ignoreConf, err := parseIgnoreFile(ctx, opt.IgnoreFile)
	if err != nil {
		return xerrors.Errorf("%s error: %w", opt.IgnoreFile, err)
	}

	for i := range report.Results {
		if err = FilterResult(ctx, &report.Results[i], ignoreConf, opt); err != nil {
			return xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
	}

	// Filter out vulnerabilities based on the given VEX document.
	if err = filterByVEX(report, opt); err != nil {
		return xerrors.Errorf("VEX error: %w", err)
	}

	return nil
}

// FilterResult filters out the result
func FilterResult(ctx context.Context, result *types.Result, ignoreConf IgnoreConfig, opt FilterOption) error {
	// Convert dbTypes.Severity to string
	severities := lo.Map(opt.Severities, func(s dbTypes.Severity, _ int) string {
		return s.String()
	})

	filterVulnerabilities(result, severities, opt.IgnoreStatuses, ignoreConf)
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

// filterByVEX determines whether a detected vulnerability should be filtered out based on the provided VEX document.
// If the VEX document is not nil and the vulnerability is either not affected or fixed according to the VEX statement,
// the vulnerability is filtered out.
func filterByVEX(report types.Report, opt FilterOption) error {
	vexDoc, err := vex.New(opt.VEXPath, report)
	if err != nil {
		return err
	} else if vexDoc == nil {
		return nil
	}

	bom, err := sbomio.NewEncoder(core.Options{}).Encode(report)
	if err != nil {
		return xerrors.Errorf("unable to encode the SBOM: %w", err)
	}

	for i, result := range report.Results {
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		vexDoc.Filter(&report.Results[i], bom)
	}
	return nil
}

func filterVulnerabilities(result *types.Result, severities []string, ignoreStatuses []dbTypes.Status, ignoreConfig IgnoreConfig) {
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

		// Check if there is a duplicate vulnerability
		key := fmt.Sprintf("%s/%s/%s/%s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, vuln.PkgPath)
		if old, ok := uniqVulns[key]; ok && !shouldOverwrite(old, vuln) {
			continue
		}
		uniqVulns[key] = vuln
	}

	// Override the detected vulnerabilities
	result.Vulnerabilities = maps.Values(uniqVulns)
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
			result.MisconfSummary.Exceptions++
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(misconf, types.FindingStatusIgnored, f.Statement, ignoreConfig.FilePath))
			continue
		}

		// Count successes, failures, and exceptions
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
	case types.MisconfStatusException:
		summary.Exceptions++
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
			result.MisconfSummary.Exceptions++
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
			continue
		}
		filteredLicenses = append(filteredLicenses, lic)
	}
	result.Licenses = filteredLicenses

	return nil
}

func evaluate(ctx context.Context, query rego.PreparedEvalQuery, input interface{}) (bool, error) {
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
