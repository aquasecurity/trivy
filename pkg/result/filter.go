package result

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/samber/lo"

	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	// DefaultIgnoreFile is the file name to be evaluated
	DefaultIgnoreFile = ".trivyignore"
)

// Filter filters out the vulnerabilities
func Filter(ctx context.Context, result *types.Result, severities []dbTypes.Severity, ignoreUnfixed, includeNonFailures bool,
	ignoreFile, policyFile string, ignoreLicenses []string) error {
	ignoredIDs := getIgnoredIDs(ignoreFile)

	filteredVulns := filterVulnerabilities(result.Vulnerabilities, severities, ignoreUnfixed, ignoredIDs)
	misconfSummary, filteredMisconfs := filterMisconfigurations(result.Misconfigurations, severities, includeNonFailures, ignoredIDs)
	result.Secrets = filterSecrets(result.Secrets, severities, ignoredIDs)
	result.Licenses = filterLicenses(result.Licenses, severities, ignoreLicenses)

	if policyFile != "" {
		var err error
		filteredVulns, filteredMisconfs, err = applyPolicy(ctx, filteredVulns, filteredMisconfs, policyFile)
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

func filterVulnerabilities(vulns []types.DetectedVulnerability, severities []dbTypes.Severity,
	ignoreUnfixed bool, ignoredIDs []string) []types.DetectedVulnerability {
	uniqVulns := make(map[string]types.DetectedVulnerability)
	for _, vuln := range vulns {
		if vuln.Severity == "" {
			vuln.Severity = dbTypes.SeverityUnknown.String()
		}
		// Filter vulnerabilities by severity
		for _, s := range severities {
			if s.String() != vuln.Severity {
				continue
			}

			// Ignore unfixed vulnerabilities
			if ignoreUnfixed && vuln.FixedVersion == "" {
				continue
			} else if slices.Contains(ignoredIDs, vuln.VulnerabilityID) {
				continue
			}

			// Check if there is a duplicate vulnerability
			key := fmt.Sprintf("%s/%s/%s/%s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, vuln.PkgPath)
			if old, ok := uniqVulns[key]; ok && !shouldOverwrite(old, vuln) {
				continue
			}
			uniqVulns[key] = vuln
			break
		}
	}
	return maps.Values(uniqVulns)
}

func filterMisconfigurations(misconfs []types.DetectedMisconfiguration, severities []dbTypes.Severity,
	includeNonFailures bool, ignoredIDs []string) (*types.MisconfSummary, []types.DetectedMisconfiguration) {
	var filtered []types.DetectedMisconfiguration
	summary := new(types.MisconfSummary)

	for _, misconf := range misconfs {
		// Filter misconfigurations by severity
		for _, s := range severities {
			if s.String() == misconf.Severity {
				if slices.Contains(ignoredIDs, misconf.ID) || slices.Contains(ignoredIDs, misconf.AVDID) {
					continue
				}

				// Count successes, failures, and exceptions
				summarize(misconf.Status, summary)

				if misconf.Status != types.StatusFailure && !includeNonFailures {
					continue
				}
				filtered = append(filtered, misconf)
				break
			}
		}
	}

	if summary.Empty() {
		return nil, nil
	}

	return summary, filtered
}

func filterSecrets(secrets []ftypes.SecretFinding, severities []dbTypes.Severity,
	ignoredIDs []string) []ftypes.SecretFinding {
	var filtered []ftypes.SecretFinding
	for _, secret := range secrets {
		// Filter secrets by severity
		for _, s := range severities {
			if s.String() == secret.Severity {
				if slices.Contains(ignoredIDs, secret.RuleID) {
					continue
				}
				filtered = append(filtered, secret)
				break
			}
		}
	}
	return filtered
}

func filterLicenses(licenses []types.DetectedLicense, severities []dbTypes.Severity, ignoredLicenses []string) []types.DetectedLicense {
	return lo.Filter(licenses, func(l types.DetectedLicense, _ int) bool {
		// Skip the license if it is included in ignored licenses.
		if slices.Contains(ignoredLicenses, l.Name) {
			return false
		}

		// Filter secrets by severity
		for _, s := range severities {
			if s.String() == l.Severity {
				return true
			}
		}
		return false
	})
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

func getIgnoredIDs(ignoreFile string) []string {
	f, err := os.Open(ignoreFile)
	if err != nil {
		// trivy must work even if no .trivyignore exist
		return nil
	}
	log.Logger.Debugf("Found an ignore file %s", ignoreFile)

	var ignoredIDs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Process all fields
		fields := strings.Fields(line)
		if len(fields) > 1 {
			exp, err := getExpirationDate(fields)
			if err != nil {
				log.Logger.Warnf("Error while parsing expiration date in .trivyignore file: %s", err)
				continue
			}
			if !exp.IsZero() {
				now := time.Now()
				if exp.Before(now) {
					continue
				}
			}
		}
		ignoredIDs = append(ignoredIDs, fields[0])
	}

	log.Logger.Debugf("These IDs will be ignored: %q", ignoredIDs)

	return ignoredIDs
}

func getExpirationDate(fields []string) (time.Time, error) {
	for _, field := range fields {
		if strings.HasPrefix(field, "exp:") {
			return time.Parse("2006-01-02", strings.TrimPrefix(field, "exp:"))
		}
	}

	return time.Time{}, nil
}

func shouldOverwrite(old, new types.DetectedVulnerability) bool {
	// The same vulnerability must be picked always.
	return old.FixedVersion < new.FixedVersion
}
