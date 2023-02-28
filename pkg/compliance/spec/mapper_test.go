package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMapSpecCheckIDToFilteredResults(t *testing.T) {
	checkIDs := map[types.Scanner][]string{
		types.MisconfigScanner: {
			"AVD-KSV012",
			"AVD-1.2.31",
			"AVD-1.2.32",
		},
		types.VulnerabilityScanner: {
			"CVE-9999-9999",
			"VULN-CRITICAL",
		},
	}
	tests := []struct {
		name     string
		checkIDs map[types.Scanner][]string
		result   types.Result
		want     map[string]types.Results
	}{
		{
			name:     "misconfiguration",
			checkIDs: checkIDs,
			result: types.Result{
				Target: "target",
				Class:  types.ClassConfig,
				Type:   ftypes.Kubernetes,
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						AVDID:  "AVD-KSV012",
						Status: types.StatusFailure,
					},
					{
						AVDID:  "AVD-KSV013",
						Status: types.StatusFailure,
					},
					{
						AVDID:  "AVD-1.2.31",
						Status: types.StatusFailure,
					},
				},
			},
			want: map[string]types.Results{
				"AVD-KSV012": {
					{
						Target: "target",
						Class:  types.ClassConfig,
						Type:   ftypes.Kubernetes,
						MisconfSummary: &types.MisconfSummary{
							Successes:  0,
							Failures:   1,
							Exceptions: 0,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								AVDID:  "AVD-KSV012",
								Status: types.StatusFailure,
							},
						},
					},
				},
				"AVD-1.2.31": {
					{
						Target: "target",
						Class:  types.ClassConfig,
						Type:   ftypes.Kubernetes,
						MisconfSummary: &types.MisconfSummary{
							Successes:  0,
							Failures:   1,
							Exceptions: 0,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								AVDID:  "AVD-1.2.31",
								Status: types.StatusFailure,
							},
						},
					},
				},
			},
		},
		{
			name:     "vulnerability",
			checkIDs: checkIDs,
			result: types.Result{
				Target: "target",
				Class:  types.ClassLangPkg,
				Type:   ftypes.GoModule,
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-9999-0001",
						Vulnerability: dbTypes.Vulnerability{
							Severity: "CRITICAL",
						},
					},
					{
						VulnerabilityID: "CVE-9999-9999",
						Vulnerability: dbTypes.Vulnerability{
							Severity: "LOW",
						},
					},
				},
			},
			want: map[string]types.Results{
				"CVE-9999-9999": {
					{
						Target: "target",
						Class:  types.ClassLangPkg,
						Type:   ftypes.GoModule,
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-9999-9999",
								Vulnerability: dbTypes.Vulnerability{
									Severity: "LOW",
								},
							},
						},
					},
				},
				"VULN-CRITICAL": {
					{
						Target: "target",
						Class:  types.ClassLangPkg,
						Type:   ftypes.GoModule,
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-9999-0001",
								Vulnerability: dbTypes.Vulnerability{
									Severity: "CRITICAL",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := spec.MapSpecCheckIDToFilteredResults(tt.result, tt.checkIDs)
			assert.Equalf(t, tt.want, got, "CheckIDs()")
		})
	}
}
