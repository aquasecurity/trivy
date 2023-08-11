package result_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestFilter(t *testing.T) {
	type args struct {
		report     types.Report
		severities []dbTypes.Severity
		vexPath    string
	}
	tests := []struct {
		name string
		args args
		want types.Report
	}{
		{
			name: "severities",
			args: args{
				report: types.Report{
					Results: []types.Result{
						{
							Vulnerabilities: []types.DetectedVulnerability{
								{
									VulnerabilityID:  "CVE-2019-0001",
									PkgName:          "foo",
									InstalledVersion: "1.2.3",
									FixedVersion:     "1.2.4",
									Vulnerability: dbTypes.Vulnerability{
										Severity: dbTypes.SeverityLow.String(),
									},
								},
								{
									VulnerabilityID:  "CVE-2019-0002",
									PkgName:          "bar",
									InstalledVersion: "1.2.3",
									FixedVersion:     "1.2.4",
									Vulnerability: dbTypes.Vulnerability{
										Severity: dbTypes.SeverityCritical.String(),
									},
								},
							},
							Misconfigurations: []types.DetectedMisconfiguration{
								{
									Type:     ftypes.Kubernetes,
									ID:       "ID100",
									Title:    "Bad Deployment",
									Message:  "something bad",
									Severity: dbTypes.SeverityCritical.String(),
									Status:   types.StatusFailure,
								},
								{
									Type:     ftypes.Kubernetes,
									ID:       "ID200",
									Title:    "Bad Pod",
									Message:  "something bad",
									Severity: dbTypes.SeverityMedium.String(),
									Status:   types.StatusPassed,
								},
							},
							Secrets: []ftypes.SecretFinding{
								{
									RuleID:    "generic-critical-rule",
									Severity:  dbTypes.SeverityCritical.String(),
									Title:     "Critical Secret should pass filter",
									StartLine: 1,
									EndLine:   2,
									Match:     "*****",
								},
								{
									RuleID:    "generic-low-rule",
									Severity:  dbTypes.SeverityLow.String(),
									Title:     "Low Secret should be ignored",
									StartLine: 3,
									EndLine:   4,
									Match:     "*****",
								},
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
				},
			},
			want: types.Report{
				Results: []types.Result{
					{
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2019-0002",
								PkgName:          "bar",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Vulnerability: dbTypes.Vulnerability{
									Severity: dbTypes.SeverityCritical.String(),
								},
							},
						},
						MisconfSummary: &types.MisconfSummary{
							Successes:  0,
							Failures:   1,
							Exceptions: 0,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							{
								Type:     ftypes.Kubernetes,
								ID:       "ID100",
								Title:    "Bad Deployment",
								Message:  "something bad",
								Severity: dbTypes.SeverityCritical.String(),
								Status:   types.StatusFailure,
							},
						},
						Secrets: []ftypes.SecretFinding{
							{
								RuleID:    "generic-critical-rule",
								Severity:  dbTypes.SeverityCritical.String(),
								Title:     "Critical Secret should pass filter",
								StartLine: 1,
								EndLine:   2,
								Match:     "*****",
							},
						},
					},
				},
			},
		},
		{
			name: "filter by VEX",
			args: args{
				report: types.Report{
					Results: types.Results{
						types.Result{
							Vulnerabilities: []types.DetectedVulnerability{
								{
									VulnerabilityID:  "CVE-2019-0001",
									PkgName:          "foo",
									PkgRef:           "pkg:golang/github.com/aquasecurity/foo@1.2.3",
									InstalledVersion: "1.2.3",
									FixedVersion:     "1.2.4",
									Vulnerability: dbTypes.Vulnerability{
										Severity: dbTypes.SeverityLow.String(),
									},
								},
								{
									VulnerabilityID:  "CVE-2019-0001",
									PkgName:          "bar",
									PkgRef:           "pkg:golang/github.com/aquasecurity/bar@1.2.3",
									InstalledVersion: "1.2.3",
									FixedVersion:     "1.2.4",
									Vulnerability: dbTypes.Vulnerability{
										Severity: dbTypes.SeverityCritical.String(),
									},
								},
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
					dbTypes.SeverityHigh,
					dbTypes.SeverityMedium,
					dbTypes.SeverityLow,
					dbTypes.SeverityUnknown,
				},
				vexPath: "testdata/openvex.json",
			},
			want: types.Report{
				Results: types.Results{
					types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2019-0001",
								PkgName:          "bar",
								PkgRef:           "pkg:golang/github.com/aquasecurity/bar@1.2.3",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Vulnerability: dbTypes.Vulnerability{
									Severity: dbTypes.SeverityCritical.String(),
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
			err := result.Filter(context.Background(), tt.args.report, result.FilterOption{
				Severities: tt.args.severities,
				VEXPath:    tt.args.vexPath,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.args.report)
		})
	}

}
func TestFilterResult(t *testing.T) {
	type args struct {
		result         types.Result
		severities     []dbTypes.Severity
		ignoreStatuses []dbTypes.Status
		ignoreFile     string
		policyFile     string
		ignoreLicenses []string
	}
	tests := []struct {
		name               string
		args               args
		wantVulns          []types.DetectedVulnerability
		wantMisconfSummary *types.MisconfSummary
		wantMisconfs       []types.DetectedMisconfiguration
		wantSecrets        []ftypes.SecretFinding
	}{
		{
			name: "happy path",
			args: args{
				result: types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0002",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityCritical.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0001",
							PkgName:          "baz",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityHigh.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0001",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityCritical.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0002",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "",
							},
						},
					},
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:     ftypes.Kubernetes,
							ID:       "ID100",
							Title:    "Bad Deployment",
							Message:  "something bad",
							Severity: dbTypes.SeverityCritical.String(),
							Status:   types.StatusFailure,
						},
						{
							Type:     ftypes.Kubernetes,
							ID:       "ID200",
							Title:    "Bad Pod",
							Message:  "something bad",
							Severity: dbTypes.SeverityMedium.String(),
							Status:   types.StatusPassed,
						},
					},
					Secrets: []ftypes.SecretFinding{
						{
							RuleID:    "generic-critical-rule",
							Severity:  dbTypes.SeverityCritical.String(),
							Title:     "Critical Secret should pass filter",
							StartLine: 1,
							EndLine:   2,
							Match:     "*****",
						},
						{
							RuleID:    "generic-low-rule",
							Severity:  dbTypes.SeverityLow.String(),
							Title:     "Low Secret should be ignored",
							StartLine: 3,
							EndLine:   4,
							Match:     "*****",
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
					dbTypes.SeverityHigh,
					dbTypes.SeverityUnknown,
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2018-0001",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2019-0002",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2018-0002",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityUnknown.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2018-0001",
					PkgName:          "baz",
					InstalledVersion: "1.2.3",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
			wantMisconfSummary: &types.MisconfSummary{
				Successes:  0,
				Failures:   1,
				Exceptions: 0,
			},
			wantMisconfs: []types.DetectedMisconfiguration{
				{
					Type:     ftypes.Kubernetes,
					ID:       "ID100",
					Title:    "Bad Deployment",
					Message:  "something bad",
					Severity: dbTypes.SeverityCritical.String(),
					Status:   types.StatusFailure,
				},
			},
			wantSecrets: []ftypes.SecretFinding{
				{
					RuleID:    "generic-critical-rule",
					Severity:  dbTypes.SeverityCritical.String(),
					Title:     "Critical Secret should pass filter",
					StartLine: 1,
					EndLine:   2,
					Match:     "*****",
				},
			},
		},
		{
			name: "happy path with ignore-unfixed",
			args: args{
				result: types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0002",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Status:           dbTypes.StatusWillNotFix,
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityHigh.String(),
							},
						},
					},
				},
				severities:     []dbTypes.Severity{dbTypes.SeverityHigh},
				ignoreStatuses: []dbTypes.Status{dbTypes.StatusWillNotFix, dbTypes.StatusEndOfLife},
			},
			wantVulns: []types.DetectedVulnerability{},
		},
		{
			name: "happy path with ignore-file",
			args: args{
				result: types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							// this vulnerability is ignored
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							// this vulnerability is ignored
							VulnerabilityID:  "CVE-2019-0002",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0003",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2022-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							// this vulnerability is ignored
							VulnerabilityID:  "CVE-2022-0002",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							// this vulnerability is ignored
							VulnerabilityID:  "CVE-2022-0003",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
					},
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:     ftypes.Kubernetes,
							ID:       "ID100",
							Title:    "Bad Deployment",
							Message:  "something bad",
							Severity: dbTypes.SeverityLow.String(),
							Status:   types.StatusFailure,
						},
					},
					Secrets: []ftypes.SecretFinding{
						{
							RuleID:    "generic-wanted-rule",
							Severity:  dbTypes.SeverityLow.String(),
							Title:     "Secret that should pass filter on rule id",
							StartLine: 1,
							EndLine:   2,
							Match:     "*****",
						},
						{
							RuleID:    "generic-unwanted-rule",
							Severity:  dbTypes.SeverityLow.String(),
							Title:     "Secret that should not pass filter on rule id",
							StartLine: 3,
							EndLine:   4,
							Match:     "*****",
						},
					},
				},
				severities: []dbTypes.Severity{dbTypes.SeverityLow},
				ignoreFile: "testdata/.trivyignore",
			},

			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-0003",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityLow.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2022-0001",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityLow.String(),
					},
				},
			},
			wantSecrets: []ftypes.SecretFinding{
				{
					RuleID:    "generic-wanted-rule",
					Severity:  dbTypes.SeverityLow.String(),
					Title:     "Secret that should pass filter on rule id",
					StartLine: 1,
					EndLine:   2,
					Match:     "*****",
				},
			},
		},
		{
			name: "happy path with a policy file",
			args: args{
				result: types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							// this vulnerability is ignored
							VulnerabilityID:  "CVE-2019-0002",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							// this vulnerability is ignored
							VulnerabilityID:  "CVE-2019-0003",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
					},
				},
				severities: []dbTypes.Severity{dbTypes.SeverityLow},
				policyFile: "./testdata/test.rego",
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-0001",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityLow.String(),
					},
				},
			},
		},
		{
			name: "happy path with duplicates, one with empty fixed version",
			args: args{
				result: types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityLow.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0002",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityCritical.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0002",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.5",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityCritical.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0001",
							PkgName:          "baz",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityHigh.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0001",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityCritical.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0002",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "",
							},
						},
						{
							VulnerabilityID:  "CVE-2018-0002",
							PkgName:          "bar",
							InstalledVersion: "2.0.0",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "",
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
					dbTypes.SeverityHigh,
					dbTypes.SeverityUnknown,
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2018-0001",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2019-0002",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.5",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2018-0002",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityUnknown.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2018-0002",
					PkgName:          "bar",
					InstalledVersion: "2.0.0",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityUnknown.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2018-0001",
					PkgName:          "baz",
					InstalledVersion: "1.2.3",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
		{
			name: "happy path with duplicates and different package paths",
			args: args{
				result: types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgPath:          "some/path/a.jar",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityCritical.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgPath:          "some/other/path/a.jar",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityCritical.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0002",
							PkgName:          "baz",
							PkgPath:          "some/path/b.jar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityHigh.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0002",
							PkgPath:          "some/path/b.jar",
							PkgName:          "baz",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: dbTypes.SeverityHigh.String(),
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0003",
							PkgPath:          "some/path/c.jar",
							PkgName:          "bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "",
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0003",
							PkgName:          "bar",
							PkgPath:          "some/path/c.jar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "",
							},
						},
						{
							VulnerabilityID:  "CVE-2019-0003",
							PkgName:          "bar",
							PkgPath:          "some/other/path/c.jar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "",
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
					dbTypes.SeverityHigh,
					dbTypes.SeverityUnknown,
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-0001",
					PkgPath:          "some/other/path/a.jar",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2019-0001",
					PkgPath:          "some/path/a.jar",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2019-0003",
					PkgName:          "bar",
					PkgPath:          "some/other/path/c.jar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityUnknown.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2019-0003",
					PkgName:          "bar",
					PkgPath:          "some/path/c.jar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityUnknown.String(),
					},
				},
				{
					VulnerabilityID:  "CVE-2019-0002",
					PkgPath:          "some/path/b.jar",
					PkgName:          "baz",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := result.FilterResult(context.Background(), &tt.args.result, result.FilterOption{
				Severities:     tt.args.severities,
				IgnoreStatuses: tt.args.ignoreStatuses,
				IgnoreFile:     tt.args.ignoreFile,
				PolicyFile:     tt.args.policyFile,
				IgnoreLicenses: tt.args.ignoreLicenses,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.wantVulns, tt.args.result.Vulnerabilities)
			assert.Equal(t, tt.wantMisconfSummary, tt.args.result.MisconfSummary)
			assert.Equal(t, tt.wantMisconfs, tt.args.result.Misconfigurations)
			assert.Equal(t, tt.wantSecrets, tt.args.result.Secrets)
		})
	}
}
