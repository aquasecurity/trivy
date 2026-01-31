package result

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
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
}

// Filter filters out the report
func Filter(ctx context.Context, report types.Report, opts FilterOptions) error {
	ignoreConf, err := ParseIgnoreFile(ctx, opts.IgnoreFile)
	if err != nil {
		return xerrors.Errorf("%s error: %w", opts.IgnoreFile, err)
	}

	for i := range report.Results {
		if err = FilterResult(ctx, &report.Results[i], ignoreConf, opts); err != nil {
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
func FilterResult(ctx context.Context, result *types.Result, ignoreConf IgnoreConfig, opt FilterOptions) error {
	// Convert dbTypes.Severity to string
	severities := xslices.Map(opt.Severities, dbTypes.Severity.String)

	filterVulnerabilities(result, severities, opt.IgnoreStatuses, ignoreConf)
	filterMisconfigurations(result, severities, opt.IncludeNonFailures, ignoreConf)
	filterSecrets(result, severities, ignoreConf)
	filterLicenses(result, severities, opt.IgnoreLicenses, ignoreConf)

	if opt.PolicyFile != "" {
		policyFile := filepath.ToSlash(filepath.Clean(opt.PolicyFile))
		if err := applyPolicy(ctx, result, policyFile); err != nil {
			return xerrors.Errorf("failed to apply the policy: %w", err)
		}
	}
	sort.Sort(types.BySeverity(result.Vulnerabilities))

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
		key := fmt.Sprintf("%s/%s/%s/%s/%s", vuln.VulnerabilityID, vuln.PkgID, vuln.PkgName, vuln.InstalledVersion, vuln.PkgPath)
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
		ids := append([]string{
			misconf.ID,
			misconf.AVDID,
		}, misconf.Aliases...)
		if f := ignoreConfig.MatchMisconfiguration(ids, result.Target); f != nil {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(misconf, types.FindingStatusIgnored, f.Statement, ignoreConfig.FilePath))
			continue
		}

		// Count successes and failures
		updateMisconfSummary(misconf.Status, result.MisconfSummary)

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

func updateMisconfSummary(status types.MisconfStatus, summary *types.MisconfSummary) {
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

	// Vulnerabilities
	filteredVulns, modifiedVulns, err := filterFindingsByRego(ctx, query, result.Vulnerabilities, policyFile)
	if err != nil {
		return err
	}
	result.Vulnerabilities = filteredVulns
	result.ModifiedFindings = append(result.ModifiedFindings, modifiedVulns...)

	// Misconfigurations
	filteredMisconfs, modifiedMisconfs, err := filterFindingsByRego(ctx, query, result.Misconfigurations, policyFile)
	if err != nil {
		return err
	}

	for _, m := range modifiedMisconfs {
		misconf, ok := m.Finding.(types.DetectedMisconfiguration)
		if !ok {
			continue
		}
		switch misconf.Status {
		case types.MisconfStatusFailure:
			result.MisconfSummary.Failures--
		case types.MisconfStatusPassed:
			result.MisconfSummary.Successes--
		}
	}

	result.Misconfigurations = filteredMisconfs
	result.ModifiedFindings = append(result.ModifiedFindings, modifiedMisconfs...)

	// Secrets
	filteredSecrets, modifiedSecrets, err := filterFindingsByRego(ctx, query, result.Secrets, policyFile)
	if err != nil {
		return err
	}
	result.Secrets = filteredSecrets
	result.ModifiedFindings = append(result.ModifiedFindings, modifiedSecrets...)

	// Licenses
	filteredLicenses, modifiedLicenses, err := filterFindingsByRego(ctx, query, result.Licenses, policyFile)
	if err != nil {
		return err
	}
	result.Licenses = filteredLicenses
	result.ModifiedFindings = append(result.ModifiedFindings, modifiedLicenses...)
	return nil
}

func filterFindingsByRego[T types.Finding](
	ctx context.Context, query rego.PreparedEvalQuery, findings []T, policyFile string,
) ([]T, []types.ModifiedFinding, error) {
	var filtered []T
	var modified []types.ModifiedFinding

	for _, finding := range findings {
		ignored, err := evaluate(ctx, query, finding)
		if err != nil {
			return nil, nil, err
		}
		if ignored {
			modified = append(modified,
				types.NewModifiedFinding(finding, types.FindingStatusIgnored, "Filtered by Rego", policyFile))
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, modified, nil
}

func evaluate[T types.Finding](ctx context.Context, query rego.PreparedEvalQuery, finding T) (bool, error) {
	type regoInput struct {
		Data T      `json:",inline"`
		Type string `json:"Type"`
	}

	ri := regoInput{
		Data: finding,
		Type: string(finding.FindingType()),
	}

	results, err := query.Eval(ctx, rego.EvalInput(ri))
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
