package spec

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

// TrivyCheck represent checks models : vulnerability , misconfiguration and secret
type TrivyCheck interface {
	GetID() string
	CheckType() string
	CheckPass() bool
}

// Mapper represent scan checks to spec check ids mapper
type Mapper[T TrivyCheck] interface {
	FilterScanResultsBySpecCheckIds(trivyChecks []T, scannerCheckIDs map[string][]string) []T
	MapSpecCheckIDToFilteredResults(trivyChecks []TrivyCheck, target string, class types.ResultClass, typeN string, scannerCheckIDs map[string][]string) map[string]types.Results
}

type mapper[T TrivyCheck] struct {
}

// NewMapper instansiate new Mapper for specific scanner type
func NewMapper[T TrivyCheck]() Mapper[T] {
	return &mapper[T]{}
}

// FilterScanResultsBySpecCheckIds create a array of filtered security checks by spec checks ids
func (m mapper[T]) FilterScanResultsBySpecCheckIds(trivyChecks []T, scannerCheckIDs map[string][]string) []T {
	filteredSecurityCheck := make([]T, 0)
	for _, tc := range trivyChecks {
		for _, id := range scannerCheckIDs[tc.CheckType()] {
			if tc.GetID() == id {
				filteredSecurityCheck = append(filteredSecurityCheck, tc)
			}
		}
	}
	return filteredSecurityCheck
}

// MapSpecCheckIDToFilteredResults map spec check id to filterred scan results
func (m mapper[T]) MapSpecCheckIDToFilteredResults(trivyChecks []TrivyCheck, target string, class types.ResultClass, typeN string, scannerCheckIDs map[string][]string) map[string]types.Results {
	mapCheckByID := make(map[string]types.Results)
	for _, tc := range trivyChecks {
		if _, ok := mapCheckByID[tc.GetID()]; !ok {
			mapCheckByID[tc.GetID()] = make(types.Results, 0)
		}
		for _, id := range scannerCheckIDs[tc.CheckType()] {
			if tc.GetID() == id {
				switch val := tc.(type) {
				case types.DetectedMisconfiguration:
					mapCheckByID[tc.GetID()] = append(mapCheckByID[tc.GetID()], types.Result{Target: target, Class: class, Type: typeN, MisconfSummary: misconfigSummary(val), Misconfigurations: []types.DetectedMisconfiguration{val}})
				case types.DetectedVulnerability:
					mapCheckByID[tc.GetID()] = append(mapCheckByID[tc.GetID()], types.Result{Target: target, Class: class, Type: typeN, Vulnerabilities: []types.DetectedVulnerability{val}})
				}
			}
		}
	}
	return mapCheckByID
}

func misconfigSummary(misconfig types.DetectedMisconfiguration) *types.MisconfSummary {
	rms := types.MisconfSummary{}
	switch misconfig.Status {
	case types.StatusPassed:
		rms.Successes = 1
	case types.StatusFailure:
		rms.Successes = 1
	case types.StatusException:
		rms.Exceptions = 1
	}
	return &rms
}

// FilterResults filter miconfiguration and vulnerabilities results by spec scanner check Ids
func FilterResults(results types.Results, scannerCheckIDs map[string][]string) types.Results {
	filteredResults := make(types.Results, 0)
	for _, result := range results {
		if len(result.Misconfigurations) > 0 {
			filteredMisconfig := NewMapper[types.DetectedMisconfiguration]().FilterScanResultsBySpecCheckIds(result.Misconfigurations, scannerCheckIDs)
			result.Misconfigurations = filteredMisconfig
		}
		if len(result.Vulnerabilities) > 0 {
			filteredVuln := NewMapper[types.DetectedVulnerability]().FilterScanResultsBySpecCheckIds(result.Vulnerabilities, scannerCheckIDs)
			result.Vulnerabilities = filteredVuln
		}
		filteredResults = append(filteredResults, result)
	}
	return filteredResults
}

// AggregateAllChecksBySpecID aggregate all scan results and map it to spec ids
func AggregateAllChecksBySpecID(multiResults []types.Results, controls []Control) map[string]types.Results {
	scannerCheckIDs := ScannerCheckIDs(controls)
	complianceArr := make(map[string]types.Results, 0)
	for _, resResult := range multiResults {
		filteredResults := FilterResults(resResult, scannerCheckIDs)
		for _, result := range filteredResults {
			if len(result.Misconfigurations) > 0 {
				cMapper := NewMapper[types.DetectedMisconfiguration]()
				misconfigMap := cMapper.MapSpecCheckIDToFilteredResults(getTrivyChecks(result.Misconfigurations), result.Target, result.Class, result.Type, scannerCheckIDs)
				for id, checks := range misconfigMap {
					if _, ok := misconfigMap[id]; !ok {
						complianceArr[id] = make(types.Results, 0)
					}
					complianceArr[id] = append(complianceArr[id], checks...)
				}
			}
			if len(result.Vulnerabilities) > 0 {
				vMapper := NewMapper[types.DetectedMisconfiguration]()
				vulnsMap := vMapper.MapSpecCheckIDToFilteredResults(getTrivyChecks(result.Vulnerabilities), result.Target, result.Class, result.Type, scannerCheckIDs)
				for id, checks := range vulnsMap {
					if _, ok := vulnsMap[id]; !ok {
						complianceArr[id] = make(types.Results, 0)
					}
					complianceArr[id] = append(complianceArr[id], checks...)
				}
			}
		}
	}
	return complianceArr
}

func getTrivyChecks[T TrivyCheck](checks []T) []TrivyCheck {
	tc := make([]TrivyCheck, 0)
	for _, check := range checks {
		tc = append(tc, check)
	}
	return tc
}
