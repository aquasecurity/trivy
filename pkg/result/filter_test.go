package result_test

import (
	"context"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

func TestFilter(t *testing.T) {
	var (
		pkg1 = ftypes.Package{
			ID:      "foo@v1.2.3",
			Name:    "foo",
			Version: "v1.2.3",
			Identifier: ftypes.PkgIdentifier{
				UID: "01",
				PURL: &packageurl.PackageURL{
					Type:      packageurl.TypeGolang,
					Namespace: "github.com/aquasecurity",
					Name:      "foo",
					Version:   "v1.2.3",
				},
			},
		}
		vuln1 = types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2019-0001",
			PkgName:          pkg1.Name,
			InstalledVersion: pkg1.Version,
			FixedVersion:     "1.2.4",
			PkgIdentifier: ftypes.PkgIdentifier{
				UID:  pkg1.Identifier.UID,
				PURL: pkg1.Identifier.PURL,
			},
			Vulnerability: dbTypes.Vulnerability{
				Severity: dbTypes.SeverityLow.String(),
			},
		}
		vuln2 = types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2019-0002",
			PkgName:          pkg1.Name,
			InstalledVersion: pkg1.Version,
			FixedVersion:     "1.2.4",
			PkgIdentifier: ftypes.PkgIdentifier{
				UID:  pkg1.Identifier.UID,
				PURL: pkg1.Identifier.PURL,
			},
			Vulnerability: dbTypes.Vulnerability{
				Severity: dbTypes.SeverityCritical.String(),
			},
		}
		vuln3 = types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2019-0003",
			PkgName:          "foo",
			InstalledVersion: "1.2.3",
			FixedVersion:     "1.2.4",
			Vulnerability: dbTypes.Vulnerability{
				Severity: dbTypes.SeverityLow.String(),
			},
		}
		vuln4 = types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2019-0004",
			PkgName:          "foo",
			InstalledVersion: "1.2.3",
			FixedVersion:     "1.2.4",
			Vulnerability: dbTypes.Vulnerability{
				Severity: dbTypes.SeverityLow.String(),
			},
		}
		vuln5 = types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2019-0005",
			PkgName:          "foo",
			InstalledVersion: "1.2.3",
			FixedVersion:     "1.2.4",
			Vulnerability: dbTypes.Vulnerability{
				Severity: dbTypes.SeverityLow.String(),
			},
		}
		vuln6 = types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2019-0006",
			PkgName:          "foo",
			InstalledVersion: "v1.2.3",
			FixedVersion:     "1.2.4",
			PkgIdentifier: ftypes.PkgIdentifier{
				PURL: &packageurl.PackageURL{
					Type:      packageurl.TypeGolang,
					Namespace: "github.com/aquasecurity",
					Name:      "foo",
					Version:   "v1.2.3",
				},
			},
			Vulnerability: dbTypes.Vulnerability{
				Severity: dbTypes.SeverityLow.String(),
			},
		}
		vuln7 = types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2019-0007",
			PkgName:          "bar",
			InstalledVersion: "v2.3.4",
			FixedVersion:     "2.3.5",
			PkgIdentifier: ftypes.PkgIdentifier{
				PURL: &packageurl.PackageURL{
					Type:      packageurl.TypeGolang,
					Namespace: "github.com/aquasecurity",
					Name:      "bar",
					Version:   "v2.3.4",
				},
			},
			Vulnerability: dbTypes.Vulnerability{
				Severity: dbTypes.SeverityLow.String(),
			},
		}
		misconf1 = types.DetectedMisconfiguration{
			Type:     "Kubernetes Security Check",
			ID:       "ID100",
			AVDID:    "AVD-ID100",
			Title:    "Bad Deployment",
			Message:  "something bad",
			Severity: dbTypes.SeverityHigh.String(),
			Status:   types.MisconfStatusFailure,
		}
		misconf2 = types.DetectedMisconfiguration{
			Type:     "Kubernetes Security Check",
			ID:       "ID200",
			AVDID:    "AVD-ID200",
			Title:    "Bad Pod",
			Message:  "something bad",
			Severity: dbTypes.SeverityLow.String(),
			Status:   types.MisconfStatusPassed,
		}
		misconf3 = types.DetectedMisconfiguration{
			Type:     "Kubernetes Security Check",
			ID:       "ID300",
			AVDID:    "AVD-ID300",
			Title:    "Bad Job",
			Message:  "something bad",
			Severity: dbTypes.SeverityLow.String(),
			Status:   types.MisconfStatusFailure,
		}
		secret1 = types.DetectedSecret{
			RuleID:    "generic-wanted-rule",
			Severity:  dbTypes.SeverityHigh.String(),
			Title:     "Secret that should pass filter on rule id",
			StartLine: 1,
			EndLine:   2,
			Match:     "*****",
		}
		secret2 = types.DetectedSecret{
			RuleID:    "generic-unwanted-rule",
			Severity:  dbTypes.SeverityLow.String(),
			Title:     "Secret that should not pass filter on rule id",
			StartLine: 3,
			EndLine:   4,
			Match:     "*****",
		}
		secret3 = types.DetectedSecret{
			RuleID:    "generic-unwanted-rule2",
			Severity:  dbTypes.SeverityLow.String(),
			Title:     "Secret that should not pass filter on rule id",
			StartLine: 5,
			EndLine:   6,
			Match:     "*****",
		}
		license1 = types.DetectedLicense{
			Name:       "GPL-3.0",
			Severity:   dbTypes.SeverityLow.String(),
			FilePath:   "usr/share/gcc/python/libstdcxx/v6/__init__.py",
			Category:   "restricted",
			Confidence: 1,
		}
		license2 = types.DetectedLicense{
			Name:       "GPL-3.0",
			Severity:   dbTypes.SeverityLow.String(),
			FilePath:   "usr/share/gcc/python/libstdcxx/v6/printers.py",
			Category:   "restricted",
			Confidence: 1,
		}
	)
	type args struct {
		report         types.Report
		severities     []dbTypes.Severity
		ignoreStatuses []dbTypes.Status
		ignoreFile     string
		policyFile     string
		vexPath        string
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
								vuln1, // filtered
								vuln2,
							},
							Misconfigurations: []types.DetectedMisconfiguration{
								misconf1,
								misconf2, // filtered
							},
							Secrets: []types.DetectedSecret{
								secret1,
								secret2, // filtered
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
					dbTypes.SeverityHigh,
				},
			},
			want: types.Report{
				Results: []types.Result{
					{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln2,
						},
						MisconfSummary: &types.MisconfSummary{
							Successes: 0,
							Failures:  1,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							misconf1,
						},
						Secrets: []types.DetectedSecret{
							secret1,
						},
					},
				},
			},
		},
		{
			name: "filter by VEX",
			args: args{
				report: types.Report{
					ArtifactName: ".",
					ArtifactType: artifact.TypeFilesystem,
					Results: types.Results{
						types.Result{
							Target:   "gobinary",
							Class:    types.ClassLangPkg,
							Type:     ftypes.GoBinary,
							Packages: []ftypes.Package{pkg1},
							Vulnerabilities: []types.DetectedVulnerability{
								vuln1,
								vuln2,
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
				ArtifactName: ".",
				ArtifactType: artifact.TypeFilesystem,
				Results: types.Results{
					types.Result{
						Target:   "gobinary",
						Class:    types.ClassLangPkg,
						Type:     ftypes.GoBinary,
						Packages: []ftypes.Package{pkg1},
						Vulnerabilities: []types.DetectedVulnerability{
							vuln2,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:      types.FindingTypeVulnerability,
								Status:    types.FindingStatusNotAffected,
								Statement: "vulnerable_code_not_in_execute_path",
								Source:    "testdata/openvex.json",
								Finding:   vuln1,
							},
						},
					},
				},
			},
		},
		{
			name: "ignore unfixed",
			args: args{
				report: types.Report{
					Results: types.Results{
						types.Result{
							Target: "debian:11 (debian 11)",
							Vulnerabilities: []types.DetectedVulnerability{
								vuln1,
								vuln2,
							},
						},
					},
				},
				severities: []dbTypes.Severity{dbTypes.SeverityHigh},
				ignoreStatuses: []dbTypes.Status{
					dbTypes.StatusWillNotFix,
					dbTypes.StatusEndOfLife,
				},
			},
			want: types.Report{
				Results: types.Results{
					{
						Target: "debian:11 (debian 11)",
					},
				},
			},
		},
		{
			name: "ignore file",
			args: args{
				report: types.Report{
					Results: types.Results{
						{
							Target: "package-lock.json",
							Class:  types.ClassLangPkg,
							Vulnerabilities: []types.DetectedVulnerability{
								vuln1, // ignored
								vuln2, // filtered by severity
								vuln3,
								vuln4,
								vuln5, // ignored
								vuln6, // ignored
							},
						},
						{
							Target: "deployment.yaml",
							Class:  types.ClassConfig,
							Misconfigurations: []types.DetectedMisconfiguration{
								misconf1,
								misconf2,
								misconf3,
							},
						},
						{
							Target: "config.yaml",
							Secrets: []types.DetectedSecret{
								secret1,
								secret2,
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityLow,
					dbTypes.SeverityHigh,
				},
				ignoreFile: "testdata/.trivyignore",
			},
			want: types.Report{
				Results: types.Results{
					{
						Target: "package-lock.json",
						Class:  types.ClassLangPkg,
						Vulnerabilities: []types.DetectedVulnerability{
							vuln3,
							vuln4,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:    types.FindingTypeVulnerability,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore",
								Finding: vuln1,
							},
							{
								Type:    types.FindingTypeVulnerability,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore",
								Finding: vuln5,
							},
							{
								Type:    types.FindingTypeVulnerability,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore",
								Finding: vuln6,
							},
						},
					},
					{
						Target: "deployment.yaml",
						Class:  types.ClassConfig,
						MisconfSummary: &types.MisconfSummary{
							Successes: 1,
							Failures:  1,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							misconf1,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:    types.FindingTypeMisconfiguration,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore",
								Finding: misconf3,
							},
						},
					},
					{
						Target: "config.yaml",
						Secrets: []types.DetectedSecret{
							secret1,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:    types.FindingTypeSecret,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore",
								Finding: secret2,
							},
						},
					},
				},
			},
		},
		{
			name: "ignore yaml",
			args: args{
				report: types.Report{
					Results: types.Results{
						{
							Target: "foo/package-lock.json",
							Vulnerabilities: []types.DetectedVulnerability{
								vuln1, // ignored
								vuln2, // filtered by severity
								vuln3, // ignored
								vuln4,
								vuln5, // ignored
								vuln6,
								vuln7, // filtered by PURL
							},
						},
						{
							Target: "app/Dockerfile",
							Misconfigurations: []types.DetectedMisconfiguration{
								misconf1, // ignored
								misconf2, // ignored
								misconf3,
							},
						},
						{
							Target: "config.yaml",
							Secrets: []types.DetectedSecret{
								secret1,
								secret2, // ignored
								secret3, // ignored
							},
						},
						{
							Target: "LICENSE.txt",
							Licenses: []types.DetectedLicense{
								license1, // ignored
								license2,
							},
						},
					},
				},
				ignoreFile: "testdata/.trivyignore.yaml",
				severities: []dbTypes.Severity{
					dbTypes.SeverityLow,
					dbTypes.SeverityHigh,
				},
			},
			want: types.Report{
				Results: types.Results{
					{
						Target: "foo/package-lock.json",
						Vulnerabilities: []types.DetectedVulnerability{
							vuln4,
							vuln6,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:    types.FindingTypeVulnerability,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: vuln1,
							},
							{
								Type:    types.FindingTypeVulnerability,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: vuln3,
							},
							{
								Type:    types.FindingTypeVulnerability,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: vuln5,
							},
							{
								Type:    types.FindingTypeVulnerability,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: vuln7,
							},
						},
					},
					{
						Target: "app/Dockerfile",
						MisconfSummary: &types.MisconfSummary{
							Successes: 0,
							Failures:  1,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							misconf3,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:    types.FindingTypeMisconfiguration,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: misconf1,
							},
							{
								Type:    types.FindingTypeMisconfiguration,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: misconf2,
							},
						},
					},
					{
						Target: "config.yaml",
						Secrets: []types.DetectedSecret{
							secret1,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:    types.FindingTypeSecret,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: secret2,
							},
							{
								Type:    types.FindingTypeSecret,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: secret3,
							},
						},
					},
					{
						Target: "LICENSE.txt",
						Licenses: []types.DetectedLicense{
							license2,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:    types.FindingTypeLicense,
								Status:  types.FindingStatusIgnored,
								Source:  "testdata/.trivyignore.yaml",
								Finding: license1,
							},
						},
					},
				},
			},
		},
		{
			name: "policy file for vulnerabilities",
			args: args{
				report: types.Report{
					Results: types.Results{
						{
							Vulnerabilities: []types.DetectedVulnerability{
								vuln1,
								vuln2, // ignored by severity
								vuln3, // ignored by check
							},
						},
					},
				},
				severities: []dbTypes.Severity{dbTypes.SeverityLow},
				policyFile: "./testdata/ignore-vuln.rego",
			},
			want: types.Report{
				Results: types.Results{
					{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln1,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:      types.FindingTypeVulnerability,
								Status:    types.FindingStatusIgnored,
								Statement: "Filtered by Rego",
								Source:    "testdata/ignore-vuln.rego",
								Finding:   vuln3,
							},
						},
					},
				},
			},
		},
		{
			name: "policy file for misconfigurations",
			args: args{
				report: types.Report{
					Results: types.Results{
						{
							Misconfigurations: []types.DetectedMisconfiguration{
								misconf1,
								misconf2,
								misconf3, // ignored by check
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityLow,
					dbTypes.SeverityHigh,
				},
				policyFile: "./testdata/ignore-misconf.rego",
			},
			want: types.Report{
				Results: types.Results{
					{
						MisconfSummary: &types.MisconfSummary{
							Successes: 1,
							Failures:  1,
						},
						Misconfigurations: []types.DetectedMisconfiguration{
							misconf1,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:      types.FindingTypeMisconfiguration,
								Status:    types.FindingStatusIgnored,
								Statement: "Filtered by Rego",
								Source:    "testdata/ignore-misconf.rego",
								Finding:   misconf3,
							},
						},
					},
				},
			},
		},
		{
			name: "ignore file for licenses and secrets",
			args: args{
				report: types.Report{
					Results: types.Results{
						{
							Licenses: []types.DetectedLicense{
								license1,
								license2,
							},
							Secrets: []types.DetectedSecret{
								secret1,
								secret2,
							},
						},
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityLow,
					dbTypes.SeverityHigh,
				},
				policyFile: "./testdata/test-ignore-policy-licenses-and-secrets.rego",
			},
			want: types.Report{
				Results: types.Results{
					{
						Licenses: []types.DetectedLicense{
							license1,
						},
						Secrets: []types.DetectedSecret{
							secret1,
						},
						ModifiedFindings: []types.ModifiedFinding{
							{
								Type:      types.FindingTypeSecret,
								Status:    types.FindingStatusIgnored,
								Statement: "Filtered by Rego",
								Source:    "testdata/test-ignore-policy-licenses-and-secrets.rego",
								Finding:   secret2,
							},
							{
								Type:      types.FindingTypeLicense,
								Status:    types.FindingStatusIgnored,
								Statement: "Filtered by Rego",
								Source:    "testdata/test-ignore-policy-licenses-and-secrets.rego",
								Finding:   license2,
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with duplicates, one with empty fixed version",
			args: args{
				report: types.Report{
					Results: types.Results{
						{
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
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
					dbTypes.SeverityHigh,
					dbTypes.SeverityUnknown,
				},
			},
			want: types.Report{
				Results: types.Results{
					{
						Vulnerabilities: []types.DetectedVulnerability{
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
				},
			},
		},
		{
			name: "happy path with duplicates and different package paths",
			args: args{
				report: types.Report{
					Results: types.Results{
						{
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
					},
				},
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
					dbTypes.SeverityHigh,
					dbTypes.SeverityUnknown,
				},
			},
			want: types.Report{
				Results: types.Results{
					{
						Vulnerabilities: []types.DetectedVulnerability{
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeTime := time.Date(2020, 8, 10, 7, 28, 17, 958601, time.UTC)
			ctx := clock.With(context.Background(), fakeTime)

			var vexSources []vex.Source
			if tt.args.vexPath != "" {
				vexSources = append(vexSources, vex.Source{
					Type:     vex.TypeFile,
					FilePath: tt.args.vexPath,
				})
			}

			err := result.Filter(ctx, tt.args.report, result.FilterOptions{
				Severities:     tt.args.severities,
				VEXSources:     vexSources,
				IgnoreStatuses: tt.args.ignoreStatuses,
				IgnoreFile:     tt.args.ignoreFile,
				PolicyFile:     tt.args.policyFile,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.args.report)
		})
	}
}
