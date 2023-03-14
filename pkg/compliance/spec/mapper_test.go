package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/fanal/secret"
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
		types.SecretScanner: {
			"SECRET-CRITICAL",
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
			name:     "secret",
			checkIDs: checkIDs,
			result: types.Result{
				Target: "target",
				Class:  types.ClassSecret,
				Secrets: []ftypes.SecretFinding{
					{
						RuleID:   "aws-access-key-id",
						Category: secret.CategoryAWS,
						Severity: "CRITICAL",
						Title:    "AWS Access Key ID",
						Code: ftypes.Code{
							Lines: []ftypes.Line{
								{
									Number:  2,
									Content: "AWS_ACCESS_KEY_ID=*****",
								},
							},
						},
					},
					{
						RuleID:   "aws-account-id",
						Category: secret.CategoryAWS,
						Severity: "HIGH",
						Title:    "AWS Account ID",
						Code: ftypes.Code{
							Lines: []ftypes.Line{
								{
									Number:  1,
									Content: "AWS_ACCOUNT_ID=*****",
								},
							},
						},
					},
				},
			},
			want: map[string]types.Results{
				"SECRET-CRITICAL": {
					{
						Target: "target",
						Class:  types.ClassSecret,
						Secrets: []ftypes.SecretFinding{
							{
								RuleID:   "aws-access-key-id",
								Category: secret.CategoryAWS,
								Severity: "CRITICAL",
								Title:    "AWS Access Key ID",
								Code: ftypes.Code{
									Lines: []ftypes.Line{
										{
											Number:  2,
											Content: "AWS_ACCESS_KEY_ID=*****",
										},
									},
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
			assert.Equalf(t, tt.want, got, "MapSpecCheckIDToFilteredResults()")
		})
	}
}
