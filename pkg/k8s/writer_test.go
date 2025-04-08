package k8s

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	roleWithMisconfig = report.Resource{
		Namespace: "default",
		Kind:      "Role",
		Name:      "system::leader-locking-kube-controller-manager",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.MisconfStatusFailure,
						Severity: "MEDIUM",
					},
				},
			},
		},
	}
	apiseverPodWithMisconfigAndInfra = report.Resource{
		Namespace: "kube-system",
		Kind:      "Pod",
		Name:      "kube-apiserver",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "KSV-ID100",
						Status:   types.MisconfStatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "KSV-ID101",
						Status:   types.MisconfStatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "KSV-ID102",
						Status:   types.MisconfStatusFailure,
						Severity: "HIGH",
					},
					{
						ID:       "KSV-ID103",
						Status:   types.MisconfStatusPassed,
						Severity: "HIGH",
					},

					{
						ID:       "KCV-ID100",
						Status:   types.MisconfStatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "KCV-ID101",
						Status:   types.MisconfStatusFailure,
						Severity: "MEDIUM",
					},
				},
			},
		},
	}
	deployLuaWithSecrets = report.Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "lua",
		Results: types.Results{
			{
				Secrets: []types.DetectedSecret{
					{
						RuleID:   "secret1",
						Severity: "CRITICAL",
					},
					{
						RuleID:   "secret2",
						Severity: "MEDIUM",
					},
				},
			},
		},
	}
	deployOrionWithMisconfigs = report.Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.MisconfStatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID101",
						Status:   types.MisconfStatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "ID102",
						Status:   types.MisconfStatusFailure,
						Severity: "HIGH",
					},
					{
						ID:       "ID103",
						Status:   types.MisconfStatusFailure,
						Severity: "CRITICAL",
					},
					{
						ID:       "ID104",
						Status:   types.MisconfStatusFailure,
						Severity: "UNKNOWN",
					},
					{
						ID:       "ID105",
						Status:   types.MisconfStatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID106",
						Status:   types.MisconfStatusFailure,
						Severity: "HIGH",
					},
				},
			},
		},
	}
	deployOrionWithSingleMisconfig = report.Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.MisconfStatusFailure,
						Severity: "LOW",
					},
				},
			},
		},
		Report: types.Report{
			Results: types.Results{
				{
					Class: types.ClassConfig,
					MisconfSummary: &types.MisconfSummary{
						Successes: 0,
						Failures:  1,
					},
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							ID:          "ID100",
							Title:       "Config file is bad",
							Description: "Your config file is not good.",
							Message:     "Oh no, a bad config.",
							PrimaryURL:  "https://google.com/search?q=bad%20config",
							Status:      types.MisconfStatusFailure,
							Severity:    "LOW",
						},
					},
				},
			},
		},
	}
	deployOrionWithVulns = report.Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2022-1111",
						Vulnerability:   dbTypes.Vulnerability{Severity: "LOW"},
					},
					{
						VulnerabilityID: "CVE-2022-2222",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
					{
						VulnerabilityID: "CVE-2022-3333",
						Vulnerability:   dbTypes.Vulnerability{Severity: "HIGH"},
					},
					{
						VulnerabilityID: "CVE-2022-4444",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-5555",
						Vulnerability:   dbTypes.Vulnerability{Severity: "UNKNOWN"},
					},
					{
						VulnerabilityID: "CVE-2022-6666",
						Vulnerability:   dbTypes.Vulnerability{Severity: "CRITICAL"},
					},
					{
						VulnerabilityID: "CVE-2022-7777",
						Vulnerability:   dbTypes.Vulnerability{Severity: "MEDIUM"},
					},
				},
			},
		},
	}

	deployOrionWithSingleVuln = report.Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						PkgID:           "foo/bar@v0.0.1",
						VulnerabilityID: "CVE-2022-1111",
						Vulnerability:   dbTypes.Vulnerability{Severity: "LOW"},
					},
				},
			},
		},
		Report: types.Report{
			Results: types.Results{
				{
					Class: types.ClassLangPkg,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							PkgName:          "foo/bar",
							VulnerabilityID:  "CVE-2022-1111",
							InstalledVersion: "v0.0.1",
							FixedVersion:     "v0.0.2",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2022-1111",
							Vulnerability:    dbTypes.Vulnerability{Severity: "LOW"},
						},
					},
				},
			},
		},
	}
)

func TestReportWrite_Table(t *testing.T) {
	allSeverities := []dbTypes.Severity{
		dbTypes.SeverityUnknown,
		dbTypes.SeverityLow,
		dbTypes.SeverityMedium,
		dbTypes.SeverityHigh,
		dbTypes.SeverityCritical,
	}

	tests := []struct {
		name           string
		report         report.Report
		opt            report.Option
		scanners       types.Scanners
		severities     []dbTypes.Severity
		reportType     string
		expectedOutput string
	}{
		{
			name: "Only config, all severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployOrionWithMisconfigs},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────────┬───────────────────┐
│ Namespace │   Resource   │ Misconfigurations │
│           │              ├───┬───┬───┬───┬───┤
│           │              │ C │ H │ M │ L │ U │
├───────────┼──────────────┼───┼───┼───┼───┼───┤
│ default   │ Deploy/orion │ 1 │ 2 │ 1 │ 2 │ 1 │
└───────────┴──────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌───────────┬──────────┬───────────────────┐
│ Namespace │ Resource │ Misconfigurations │
│           │          ├───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Single misconfig with `--report all`",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployOrionWithSingleMisconfig},
			},
			scanners: types.Scanners{types.MisconfigScanner},
			severities: []dbTypes.Severity{
				dbTypes.SeverityCritical,
			},
			reportType: report.AllReport,
			expectedOutput: `namespace: default, deploy: orion ()
====================================
Tests: 1 (SUCCESSES: 0, FAILURES: 1)
Failures: 0 (CRITICAL: 0)

 (LOW): Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────`,
		},
		{
			name: "Only vuln, all severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployOrionWithVulns},
			},
			scanners:   types.Scanners{types.VulnerabilityScanner},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────────┬───────────────────┐
│ Namespace │   Resource   │  Vulnerabilities  │
│           │              ├───┬───┬───┬───┬───┤
│           │              │ C │ H │ M │ L │ U │
├───────────┼──────────────┼───┼───┼───┼───┼───┤
│ default   │ Deploy/orion │ 2 │ 1 │ 2 │ 1 │ 1 │
└───────────┴──────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌───────────┬──────────┬───────────────────┐
│ Namespace │ Resource │  Vulnerabilities  │
│           │          ├───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Single vuln with `--report all`",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployOrionWithSingleVuln},
			},
			scanners: types.Scanners{types.VulnerabilityScanner},
			severities: []dbTypes.Severity{
				dbTypes.SeverityLow,
			},
			reportType: report.AllReport,
			expectedOutput: `namespace: default, deploy: orion ()
====================================
Total: 1 (LOW: 1)

┌─────────┬───────────────┬──────────┬─────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
│ Library │ Vulnerability │ Severity │ Status  │ Installed Version │ Fixed Version │                   Title                   │
├─────────┼───────────────┼──────────┼─────────┼───────────────────┼───────────────┼───────────────────────────────────────────┤
│ foo/bar │ CVE-2022-1111 │ LOW      │ unknown │ v0.0.1            │ v0.0.2        │ https://avd.aquasec.com/nvd/cve-2022-1111 │
└─────────┴───────────────┴──────────┴─────────┴───────────────────┴───────────────┴───────────────────────────────────────────┘`,
		},
		{
			name: "Only rbac, all severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{roleWithMisconfig},
			},
			scanners:   types.Scanners{types.RBACScanner},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

RBAC Assessment
┌───────────┬─────────────────────────────────────────────────────┬───────────────────┐
│ Namespace │                      Resource                       │  RBAC Assessment  │
│           │                                                     ├───┬───┬───┬───┬───┤
│           │                                                     │ C │ H │ M │ L │ U │
├───────────┼─────────────────────────────────────────────────────┼───┼───┼───┼───┼───┤
│ default   │ Role/system::leader-locking-kube-controller-manager │   │   │ 1 │   │   │
└───────────┴─────────────────────────────────────────────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Only secret, all severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployLuaWithSecrets},
			},
			scanners:   types.Scanners{types.SecretScanner},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬────────────┬───────────────────┐
│ Namespace │  Resource  │      Secrets      │
│           │            ├───┬───┬───┬───┬───┤
│           │            │ C │ H │ M │ L │ U │
├───────────┼────────────┼───┼───┼───┼───┼───┤
│ default   │ Deploy/lua │ 1 │   │ 1 │   │   │
└───────────┴────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌───────────┬──────────┬───────────────────┐
│ Namespace │ Resource │      Secrets      │
│           │          ├───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, only infra and severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────┬───────────────────┐
│ Namespace │ Resource │ Misconfigurations │
│           │          ├───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌─────────────┬────────────────────┬───────────────────┐
│  Namespace  │      Resource      │ Misconfigurations │
│             │                    ├───┬───┬───┬───┬───┤
│             │                    │ C │ H │ M │ L │ U │
├─────────────┼────────────────────┼───┼───┼───┼───┼───┤
│ kube-system │ Pod/kube-apiserver │   │ 1 │ 2 │ 2 │   │
└─────────────┴────────────────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, vuln,config,secret and severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners: types.Scanners{
				types.VulnerabilityScanner,
				types.MisconfigScanner,
				types.SecretScanner,
			},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────┬───────────────────┬───────────────────┬───────────────────┐
│ Namespace │ Resource │  Vulnerabilities  │ Misconfigurations │      Secrets      │
│           │          ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌─────────────┬────────────────────┬───────────────────┬───────────────────┬───────────────────┐
│  Namespace  │      Resource      │  Vulnerabilities  │ Misconfigurations │      Secrets      │
│             │                    ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│             │                    │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
├─────────────┼────────────────────┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
│ kube-system │ Pod/kube-apiserver │   │   │   │   │   │   │ 1 │ 2 │ 2 │   │   │   │   │   │   │
└─────────────┴────────────────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, all misconfig and vuln scanners and severities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners: types.Scanners{
				types.MisconfigScanner,
				types.VulnerabilityScanner,
			},
			severities: allSeverities,
			reportType: report.SummaryReport,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌───────────┬──────────┬───────────────────┬───────────────────┐
│ Namespace │ Resource │  Vulnerabilities  │ Misconfigurations │
│           │          ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌─────────────┬────────────────────┬───────────────────┬───────────────────┐
│  Namespace  │      Resource      │  Vulnerabilities  │ Misconfigurations │
│             │                    ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│             │                    │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
├─────────────┼────────────────────┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
│ kube-system │ Pod/kube-apiserver │   │   │   │   │   │   │ 1 │ 2 │ 2 │   │
└─────────────┴────────────────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRIVY_DISABLE_VEX_NOTICE", "true")
			output := bytes.Buffer{}

			opt := report.Option{
				Format:     "table",
				Report:     tc.reportType,
				Output:     &output,
				Scanners:   tc.scanners,
				Severities: tc.severities,
			}

			err := Write(t.Context(), tc.report, opt)
			require.NoError(t, err)
			got := stripAnsi(output.String())
			got = strings.ReplaceAll(got, "\r\n", "\n")
			assert.Equal(t, tc.expectedOutput, got, tc.name)
		})
	}
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var ansiRegexp = regexp.MustCompile(ansi)

func stripAnsi(str string) string {
	return strings.TrimSpace(ansiRegexp.ReplaceAllString(str, ""))
}
