package result

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/open-policy-agent/opa/rego"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
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
	// Filter out vulnerabilities based on the given VEX document.
	if err := filterByVEX(report, opt); err != nil {
		return xerrors.Errorf("VEX error: %w", err)
	}

	ignoreConf, err := getIgnoredFindings(opt.IgnoreFile)
	if err != nil {
		return xerrors.Errorf("%s error: %w", opt.IgnoreFile, err)
	}

	for i := range report.Results {
		if err = FilterResult(ctx, &report.Results[i], ignoreConf, opt); err != nil {
			return xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
	}
	return nil
}

// FilterResult filters out the result
func FilterResult(ctx context.Context, result *types.Result, ignoreConf IgnoreConfig, opt FilterOption) error {
	// Convert dbTypes.Severity to string
	severities := lo.Map(opt.Severities, func(s dbTypes.Severity, _ int) string {
		return s.String()
	})

	filteredVulns := filterVulnerabilities(result, severities, opt.IgnoreStatuses, ignoreConf.Vulnerabilities)
	misconfSummary, filteredMisconfs := filterMisconfigurations(result, severities, opt.IncludeNonFailures, ignoreConf.Misconfigurations)
	result.Secrets = filterSecrets(result, severities, ignoreConf.Secrets)
	result.Licenses = filterLicenses(result.Licenses, severities, opt.IgnoreLicenses, ignoreConf.Licenses)

	if opt.PolicyFile != "" {
		var err error
		filteredVulns, filteredMisconfs, err = applyPolicy(ctx, filteredVulns, filteredMisconfs, opt.PolicyFile)
		if err != nil {
			return xerrors.Errorf("failed to apply the policy: %w", err)
		}
	}
	sort.Sort(types.BySeverity(filteredVulns))

	result.Vulnerabilities = filteredVulns
	result.Misconfigurations = filteredMisconfs
	result.MisconfSummary = misconfSummary

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

	for i, result := range report.Results {
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		report.Results[i].Vulnerabilities = vexDoc.Filter(result.Vulnerabilities)
	}
	return nil
}

func filterVulnerabilities(result *types.Result, severities []string, ignoreStatuses []dbTypes.Status,
	ignoreFindings IgnoreFindings) []types.DetectedVulnerability {
	uniqVulns := make(map[string]types.DetectedVulnerability)

	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity == "" {
			vuln.Severity = dbTypes.SeverityUnknown.String()
		}

		if !slices.Contains(severities, vuln.Severity) {
			// Filter by severity
			continue
		} else if slices.Contains(ignoreStatuses, vuln.Status) {
			// Filter by status
			continue
		} else if ignoreFindings.Match(result.Target, vuln.VulnerabilityID) ||
			ignoreFindings.Match(vuln.PkgPath, vuln.VulnerabilityID) {
			// Filter by ignore file
			continue
		}

		// Check if there is a duplicate vulnerability
		key := fmt.Sprintf("%s/%s/%s/%s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, vuln.PkgPath)
		if old, ok := uniqVulns[key]; ok && !shouldOverwrite(old, vuln) {
			continue
		}
		uniqVulns[key] = vuln
	}
	if len(uniqVulns) == 0 {
		return nil
	}
	return maps.Values(uniqVulns)
}

func filterMisconfigurations(result *types.Result, severities []string, includeNonFailures bool,
	ignoreMisconfs IgnoreFindings) (*types.MisconfSummary, []types.DetectedMisconfiguration) {
	var filtered []types.DetectedMisconfiguration
	summary := new(types.MisconfSummary)

	for _, misconf := range result.Misconfigurations {
		if !slices.Contains(severities, misconf.Severity) {
			// Filter by severity
			continue
		} else if ignoreMisconfs.Match(result.Target, misconf.ID) || ignoreMisconfs.Match(result.Target, misconf.AVDID) {
			// Filter misconfigurations by ignore file
			continue
		}

		// Count successes, failures, and exceptions
		summarize(misconf.Status, summary)

		if misconf.Status != types.StatusFailure && !includeNonFailures {
			continue
		}
		filtered = append(filtered, misconf)
	}

	if summary.Empty() {
		return nil, nil
	}

	return summary, filtered
}

func filterSecrets(result *types.Result, severities []string, ignoreFindings IgnoreFindings) []ftypes.SecretFinding {
	var filtered []ftypes.SecretFinding
	for _, secret := range result.Secrets {
		if !slices.Contains(severities, secret.Severity) {
			// Filter by severity
			continue
		} else if ignoreFindings.Match(result.Target, secret.RuleID) {
			// Filter by ignore file
			continue
		}
		filtered = append(filtered, secret)
	}
	return filtered
}

func filterLicenses(licenses []types.DetectedLicense, severities, ignoreLicenseNames []string, ignoreFindings IgnoreFindings) []types.DetectedLicense {
	// Merge ignore license names into ignored findings
	for _, licenseName := range ignoreLicenseNames {
		ignoreFindings = append(ignoreFindings, IgnoreFinding{
			ID: licenseName,
		})
	}

	var filtered []types.DetectedLicense
	for _, l := range licenses {
		if !slices.Contains(severities, l.Severity) {
			// Filter by severity
			continue
		} else if ignoreFindings.Match(l.FilePath, l.Name) {
			// Filter by ignore file or ignore license names
			continue
		}
		filtered = append(filtered, l)
	}
	return filtered
}

func summarize(status types.MisconfStatus, summary *types.MisconfSummary) {
	switch status {
	case types.StatusFailure:
		summary.Failures++
	case types.StatusPassed:
		summary.Successes++
	case types.StatusException:
		summary.Exceptions++
	}
}

func applyPolicy(ctx context.Context, vulns []types.DetectedVulnerability, misconfs []types.DetectedMisconfiguration,
	policyFile string) ([]types.DetectedVulnerability, []types.DetectedMisconfiguration, error) {
	policy, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to read the policy file: %w", err)
	}

	query, err := rego.New(
		rego.Query("data.trivy.ignore"),
		rego.Module("lib.rego", module),
		rego.Module("trivy.rego", string(policy)),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to prepare for eval: %w", err)
	}

	// Vulnerabilities
	var filteredVulns []types.DetectedVulnerability
	for _, vuln := range vulns {
		ignored, err := evaluate(ctx, query, vuln)
		if err != nil {
			return nil, nil, err
		}
		if ignored {
			continue
		}
		filteredVulns = append(filteredVulns, vuln)
	}

	// Misconfigurations
	var filteredMisconfs []types.DetectedMisconfiguration
	for _, misconf := range misconfs {
		ignored, err := evaluate(ctx, query, misconf)
		if err != nil {
			return nil, nil, err
		}
		if ignored {
			continue
		}
		filteredMisconfs = append(filteredMisconfs, misconf)
	}
	return filteredVulns, filteredMisconfs, nil
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

func shouldOverwrite(old, new types.DetectedVulnerability) bool {
	// The same vulnerability must be picked always.
	return old.FixedVersion < new.FixedVersion
}
