package spec_test

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFilterScanResultsBySpecCheckIds(t *testing.T) {
	tests := []struct {
		name        string
		specPath    string
		trivyCheck  spec.TrivyCheck
		wantMapping map[string][]spec.TrivyCheck
	}{
		{name: "filter results by check ids for config", specPath: "./testdata/mapping_spec.yaml", trivyCheck: types.DetectedMisconfiguration{AVDID: "KSV012"},
			wantMapping: map[string][]spec.TrivyCheck{"KSV012": {types.DetectedMisconfiguration{AVDID: "KSV012"}}}},
		{name: "filter results by check ids for vulns", specPath: "./testdata/mapping_spec.yaml", trivyCheck: types.DetectedVulnerability{VulnerabilityID: "KSV014"},
			wantMapping: map[string][]spec.TrivyCheck{"KSV014": {types.DetectedVulnerability{VulnerabilityID: "KSV014"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := ReadSpecFile(tt.specPath)
			assert.NoError(t, err)
			scannerIDMap := spec.ScannerCheckIDs(cr.Spec.Controls)
			m := spec.NewMapper[spec.TrivyCheck]()
			filteredResults := m.FilterScanResultsBySpecCheckIds([]spec.TrivyCheck{tt.trivyCheck}, scannerIDMap)
			for _, v := range filteredResults {
				assert.Equal(t, len(tt.wantMapping[v.GetID()]), 1)
			}
		})
	}
}

func TestFilterResults(t *testing.T) {
	tests := []struct {
		name         string
		specPath     string
		results      types.Results
		wantFiltered types.Results
	}{
		{name: "filter results by check ids define in spec", specPath: "./testdata/mapping_spec.yaml",
			results:      types.Results{{Misconfigurations: []types.DetectedMisconfiguration{{AVDID: "AVD-KSV012"}, {AVDID: "AVD-KSV017"}}, Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-KSV014"}}}},
			wantFiltered: types.Results{{Misconfigurations: []types.DetectedMisconfiguration{{AVDID: "AVD-KSV012"}}, Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-KSV014"}}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := ReadSpecFile(tt.specPath)
			assert.NoError(t, err)
			scannerIDMap := spec.ScannerCheckIDs(cr.Spec.Controls)
			r := spec.FilterResults(tt.results, scannerIDMap)
			assert.Equal(t, r, tt.wantFiltered)
		})
	}
}

func TestMapSpecCheckIDtoFilteredResults(t *testing.T) {
	tests := []struct {
		name        string
		specPath    string
		trivyCheck  spec.TrivyCheck
		wantMapping map[string]types.Results
	}{
		{name: "map Check by ID config", specPath: "./testdata/mapping_spec.yaml", trivyCheck: types.DetectedMisconfiguration{AVDID: "AVD-KSV012"},
			wantMapping: map[string]types.Results{"AVD-KSV012": {types.Result{Target: "target", MisconfSummary: &types.MisconfSummary{Successes: 0, Failures: 0, Exceptions: 0}, Class: "class", Type: "typeN", Misconfigurations: []types.DetectedMisconfiguration{{AVDID: "AVD-KSV012"}}}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := ReadSpecFile(tt.specPath)
			assert.NoError(t, err)
			scannerIDMap := spec.ScannerCheckIDs(cr.Spec.Controls)
			m := spec.NewMapper[spec.TrivyCheck]()
			mapResults := m.MapSpecCheckIDToFilteredResults([]spec.TrivyCheck{tt.trivyCheck}, "target", "class", "typeN", scannerIDMap)
			for key, val := range tt.wantMapping {
				assert.Equal(t, mapResults[key], val)
			}
		})
	}
}
