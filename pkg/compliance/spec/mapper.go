package spec

import (
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/types"
)

// MapSpecCheckIDToFilteredResults map spec check id to filtered scan results
func MapSpecCheckIDToFilteredResults(result types.Result, checkIDs map[types.SecurityCheck][]string) map[string]types.Results {
	mapCheckByID := make(map[string]types.Results)
	for _, vuln := range result.Vulnerabilities {
		// Skip irrelevant check IDs
		if !slices.Contains(checkIDs[types.SecurityCheckVulnerability], vuln.GetID()) {
			continue
		}
		mapCheckByID[vuln.GetID()] = append(mapCheckByID[vuln.GetID()], types.Result{
			Target:          result.Target,
			Class:           result.Class,
			Type:            result.Type,
			Vulnerabilities: []types.DetectedVulnerability{vuln},
		})
	}
	for _, m := range result.Misconfigurations {
		// Skip irrelevant check IDs
		if !slices.Contains(checkIDs[types.SecurityCheckConfig], m.GetID()) {
			continue
		}

		mapCheckByID[m.GetID()] = append(mapCheckByID[m.GetID()], types.Result{
			Target:            result.Target,
			Class:             result.Class,
			Type:              result.Type,
			MisconfSummary:    misconfigSummary(m),
			Misconfigurations: []types.DetectedMisconfiguration{m},
		})
	}
	return mapCheckByID
}

func misconfigSummary(misconfig types.DetectedMisconfiguration) *types.MisconfSummary {
	rms := types.MisconfSummary{}
	switch misconfig.Status {
	case types.StatusPassed:
		rms.Successes = 1
	case types.StatusFailure:
		rms.Failures = 1
	case types.StatusException:
		rms.Exceptions = 1
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
