package k8s

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	AllReport     = "all"
	SummaryReport = "summary"

	tableFormat     = "table"
	jsonFormat      = "json"
	cycloneDXFormat = "cyclonedx"
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
)

func TestReportWrite_Summary(t *testing.T) {
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
		expectedOutput string
	}{
		{
			name: "Only config, all serverities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployOrionWithMisconfigs},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			severities: allSeverities,
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
			name: "Only vuln, all serverities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployOrionWithVulns},
			},
			scanners:   types.Scanners{types.VulnerabilityScanner},
			severities: allSeverities,
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
			name: "Only rbac, all serverities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{roleWithMisconfig},
			},
			scanners:   types.Scanners{types.RBACScanner},
			severities: allSeverities,
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
			name: "Only secret, all serverities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{deployLuaWithSecrets},
			},
			scanners:   types.Scanners{types.SecretScanner},
			severities: allSeverities,
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
			name: "apiserver, only infra and serverities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			severities: allSeverities,
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
			name: "apiserver, vuln,config,secret and serverities",
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
			name: "apiserver, all misconfig and vuln scanners and serverities",
			report: report.Report{
				ClusterName: "test",
				Resources:   []report.Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners: types.Scanners{
				types.MisconfigScanner,
				types.VulnerabilityScanner,
			},
			severities: allSeverities,
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
			output := bytes.Buffer{}

			opt := report.Option{
				Format:     "table",
				Report:     "summary",
				Output:     &output,
				Scanners:   tc.scanners,
				Severities: tc.severities,
			}

			err := Write(context.Background(), tc.report, opt)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, stripAnsi(output.String()), tc.name)
		})
	}
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var ansiRegexp = regexp.MustCompile(ansi)

func stripAnsi(str string) string {
	return strings.TrimSpace(ansiRegexp.ReplaceAllString(str, ""))
}
