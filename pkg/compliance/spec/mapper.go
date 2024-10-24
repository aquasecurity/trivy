package spec

import (
	"slices"

	"github.com/aquasecurity/trivy/pkg/types"
)

// MapSpecCheckIDToFilteredResults map spec check id to filtered scan results
func MapSpecCheckIDToFilteredResults(result types.Result, checkIDs map[types.Scanner][]string) map[string]types.Results {
	mapCheckByID := make(map[string]types.Results)
	for _, vuln := range result.Vulnerabilities {
		// Skip irrelevant check IDs
		if !slices.Contains(checkIDs[types.VulnerabilityScanner], vuln.VulnerabilityID) {
			continue
		}
		mapCheckByID[vuln.VulnerabilityID] = append(mapCheckByID[vuln.VulnerabilityID], types.Result{
			Target:          result.Target,
			Class:           result.Class,
			Type:            result.Type,
			Vulnerabilities: []types.DetectedVulnerability{vuln},
		})
	}
	for _, m := range result.Misconfigurations {
		// Skip irrelevant check IDs
		if !slices.Contains(checkIDs[types.MisconfigScanner], m.AVDID) {
			continue
		}

		mapCheckByID[m.AVDID] = append(mapCheckByID[m.AVDID], types.Result{
			Target:            result.Target,
			Class:             result.Class,
			Type:              result.Type,
			MisconfSummary:    misconfigSummary(m),
			Misconfigurations: []types.DetectedMisconfiguration{m},
		})
	}

	// Evaluate custom IDs
	mapCustomIDsToFilteredResults(result, checkIDs, mapCheckByID)

	return mapCheckByID
}

func misconfigSummary(misconfig types.DetectedMisconfiguration) *types.MisconfSummary {
	rms := types.MisconfSummary{}
	switch misconfig.Status {
	case types.MisconfStatusPassed:
		rms.Successes = 1
	case types.MisconfStatusFailure:
		rms.Failures = 1
	}
	return &rms
}

// AggregateAllChecksBySpecID aggregates all scan results and map it to spec ids
func AggregateAllChecksBySpecID(multiResults []types.Results, cs ComplianceSpec) map[string]types.Results {
	checkIDs := cs.CheckIDs()
	complianceArr := make(map[string]types.Results, 0)
	for _, resResult := range multiResults {
		for _, result := range resResult {
			m := MapSpecCheckIDToFilteredResults(result, checkIDs)
			for id, checks := range m {
				complianceArr[id] = append(complianceArr[id], checks...)
			}
		}
	}
	return complianceArr
}
