package spec

import (
	"github.com/samber/lo"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// We might be going to rewrite these functions in Rego,
// but we'll keep them for now until we need flexibility.
var customIDs = map[string]func(types.Result) types.Result{
	"VULN-CRITICAL":   filterCriticalVulns,
	"VULN-HIGH":       filterHighVulns,
	"SECRET-CRITICAL": filterCriticalSecrets,
	"SECRET-HIGH":     filterHighSecrets,
}

func mapCustomIDsToFilteredResults(result types.Result, checkIDs map[types.Scanner][]string,
	mapCheckByID map[string]types.Results) {
	for _, ids := range checkIDs {
		for _, id := range ids {
			filterFunc, ok := customIDs[id]
			if !ok {
				continue
			}
			filtered := filterFunc(result)
			if filtered.IsEmpty() {
				continue
			}
			mapCheckByID[id] = types.Results{filtered}
		}
	}
}

func filterCriticalVulns(result types.Result) types.Result {
	return filterVulns(result, dbTypes.SeverityCritical)
}

func filterHighVulns(result types.Result) types.Result {
	return filterVulns(result, dbTypes.SeverityHigh)
}

func filterVulns(result types.Result, severity dbTypes.Severity) types.Result {
	filtered := lo.Filter(result.Vulnerabilities, func(vuln types.DetectedVulnerability, _ int) bool {
		return vuln.Severity == severity.String()
	})
	return types.Result{
		Target:          result.Target,
		Class:           result.Class,
		Type:            result.Type,
		Vulnerabilities: filtered,
	}
}

func filterCriticalSecrets(result types.Result) types.Result {
	return filterSecrets(result, dbTypes.SeverityCritical)
}

func filterHighSecrets(result types.Result) types.Result {
	return filterSecrets(result, dbTypes.SeverityHigh)
}

func filterSecrets(result types.Result, severity dbTypes.Severity) types.Result {
	filtered := lo.Filter(result.Secrets, func(vuln ftypes.SecretFinding, _ int) bool {
		return vuln.Severity == severity.String()
	})
	return types.Result{
		Target:  result.Target,
		Class:   result.Class,
		Type:    result.Type,
		Secrets: filtered,
	}
}
