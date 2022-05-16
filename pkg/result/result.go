package result

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/wire"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	// DefaultIgnoreFile is the file name to be evaluated
	DefaultIgnoreFile = ".trivyignore"
)

var (
	primaryURLPrefixes = map[dbTypes.SourceID][]string{
		vulnerability.Debian:           {"http://www.debian.org", "https://www.debian.org"},
		vulnerability.Ubuntu:           {"http://www.ubuntu.com", "https://usn.ubuntu.com"},
		vulnerability.RedHat:           {"https://access.redhat.com"},
		vulnerability.SuseCVRF:         {"http://lists.opensuse.org", "https://lists.opensuse.org"},
		vulnerability.OracleOVAL:       {"http://linux.oracle.com/errata", "https://linux.oracle.com/errata"},
		vulnerability.NodejsSecurityWg: {"https://www.npmjs.com", "https://hackerone.com"},
		vulnerability.RubySec:          {"https://groups.google.com"},
	}
)

// SuperSet binds the dependencies
var SuperSet = wire.NewSet(
	wire.Struct(new(db.Config)),
	NewClient,
)

// Client implements db operations
type Client struct {
	dbc db.Operation
}

// NewClient is the factory method for Client
func NewClient(dbc db.Config) Client {
	return Client{dbc: dbc}
}

// FillVulnerabilityInfo fills extra info in vulnerability objects
func (c Client) FillVulnerabilityInfo(vulns []types.DetectedVulnerability, reportType string) {
	for i := range vulns {
		vulnID := vulns[i].VulnerabilityID
		vuln, err := c.dbc.GetVulnerability(vulnID)
		if err != nil {
			log.Logger.Warnf("Error while getting vulnerability details: %s\n", err)
			continue
		}

		// Detect the data source
		var source dbTypes.SourceID
		if vulns[i].DataSource != nil {
			source = vulns[i].DataSource.ID
		}

		// Select the severity according to the detected source.
		severity, severitySource := c.getVendorSeverity(&vuln, source)

		// The vendor might provide package-specific severity like Debian.
		// For example, CVE-2015-2328 in Debian has "unimportant" for mongodb and "low" for pcre3.
		// In that case, we keep the severity as is.
		if vulns[i].SeveritySource != "" {
			severity = vulns[i].Severity
			severitySource = vulns[i].SeveritySource
		}

		// Add the vulnerability detail
		vulns[i].Vulnerability = vuln

		vulns[i].Severity = severity
		vulns[i].SeveritySource = severitySource
		vulns[i].PrimaryURL = c.getPrimaryURL(vulnID, vuln.References, source)
	}
}

func (c Client) getVendorSeverity(vuln *dbTypes.Vulnerability, source dbTypes.SourceID) (string, dbTypes.SourceID) {
	if vs, ok := vuln.VendorSeverity[source]; ok {
		return vs.String(), source
	}

	// Try NVD as a fallback if it exists
	if vs, ok := vuln.VendorSeverity[vulnerability.NVD]; ok {
		return vs.String(), vulnerability.NVD
	}

	if vuln.Severity == "" {
		return dbTypes.SeverityUnknown.String(), ""
	}

	return vuln.Severity, ""
}

func (c Client) getPrimaryURL(vulnID string, refs []string, source dbTypes.SourceID) string {
	switch {
	case strings.HasPrefix(vulnID, "CVE-"):
		return "https://avd.aquasec.com/nvd/" + strings.ToLower(vulnID)
	case strings.HasPrefix(vulnID, "RUSTSEC-"):
		return "https://osv.dev/vulnerability/" + vulnID
	case strings.HasPrefix(vulnID, "GHSA-"):
		return "https://github.com/advisories/" + vulnID
	case strings.HasPrefix(vulnID, "TEMP-"):
		return "https://security-tracker.debian.org/tracker/" + vulnID
	}

	prefixes := primaryURLPrefixes[source]
	for _, pre := range prefixes {
		for _, ref := range refs {
			if strings.HasPrefix(ref, pre) {
				return ref
			}
		}
	}
	return ""
}

// Filter filter out the vulnerabilities
func (c Client) Filter(ctx context.Context, vulns []types.DetectedVulnerability, misconfs []types.DetectedMisconfiguration, secrets []ftypes.SecretFinding,
	severities []dbTypes.Severity, ignoreUnfixed, includeNonFailures bool, ignoreFile, policyFile string) (
	[]types.DetectedVulnerability, *types.MisconfSummary, []types.DetectedMisconfiguration, []ftypes.SecretFinding, error) {
	ignoredIDs := getIgnoredIDs(ignoreFile)

	filteredVulns := filterVulnerabilities(vulns, severities, ignoreUnfixed, ignoredIDs)
	misconfSummary, filteredMisconfs := filterMisconfigurations(misconfs, severities, includeNonFailures, ignoredIDs)
	filteredSecrets := filterSecrets(secrets, severities)

	if policyFile != "" {
		var err error
		filteredVulns, filteredMisconfs, err = applyPolicy(ctx, filteredVulns, filteredMisconfs, policyFile)
		if err != nil {
			return nil, nil, nil, nil, xerrors.Errorf("failed to apply the policy: %w", err)
		}
	}
	sort.Sort(types.BySeverity(filteredVulns))

	return filteredVulns, misconfSummary, filteredMisconfs, filteredSecrets, nil
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
			key := fmt.Sprintf("%s/%s/%s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion)
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
				if slices.Contains(ignoredIDs, misconf.ID) {
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

func filterSecrets(secrets []ftypes.SecretFinding, severities []dbTypes.Severity) []ftypes.SecretFinding {
	var filtered []ftypes.SecretFinding
	for _, secret := range secrets {
		// Filter secrets by severity
		for _, s := range severities {
			if s.String() == secret.Severity {
				filtered = append(filtered, secret)
				break
			}
		}
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
		ignoredIDs = append(ignoredIDs, line)
	}

	log.Logger.Debugf("These IDs will be ignored: %q", ignoredIDs)

	return ignoredIDs
}

func shouldOverwrite(old, new types.DetectedVulnerability) bool {
	// The same vulnerability must be picked always.
	return old.FixedVersion < new.FixedVersion
}
