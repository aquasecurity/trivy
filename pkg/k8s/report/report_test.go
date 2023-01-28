package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	deployOrionWithMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "ID102",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
					{
						ID:       "ID103",
						Status:   types.StatusFailure,
						Severity: "CRITICAL",
					},
					{
						ID:       "ID104",
						Status:   types.StatusFailure,
						Severity: "UNKNOWN",
					},
					{
						ID:       "ID105",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID106",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
				},
			},
		},
	}

	deployOrionWithVulns = Resource{
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

	deployOrionWithBothVulnsAndMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "ID102",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
					{
						ID:       "ID103",
						Status:   types.StatusFailure,
						Severity: "CRITICAL",
					},
					{
						ID:       "ID104",
						Status:   types.StatusFailure,
						Severity: "UNKNOWN",
					},
					{
						ID:       "ID105",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "ID106",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},
				},
			},
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

	cronjobHelloWithVulns = Resource{
		Namespace: "default",
		Kind:      "Cronjob",
		Name:      "hello",
		Results: types.Results{
			{Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-2020-9999"}}},
		},
	}

	podPrometheusWithMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Pod",
		Name:      "prometheus",
		Results: types.Results{
			{Misconfigurations: []types.DetectedMisconfiguration{{ID: "ID100"}}},
		},
	}

	roleWithMisconfig = Resource{
		Namespace: "default",
		Kind:      "Role",
		Name:      "system::leader-locking-kube-controller-manager",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "ID100",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
				},
			},
		},
	}

	deployLuaWithSecrets = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "lua",
		Results: types.Results{
			{
				Secrets: []ftypes.SecretFinding{
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

	apiseverPodWithMisconfigAndInfra = Resource{
		Namespace: "kube-system",
		Kind:      "Pod",
		Name:      "kube-apiserver",
		Results: types.Results{
			{
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:       "KSV-ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "KSV-ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
					{
						ID:       "KSV-ID102",
						Status:   types.StatusFailure,
						Severity: "HIGH",
					},

					{
						ID:       "KCV-ID100",
						Status:   types.StatusFailure,
						Severity: "LOW",
					},
					{
						ID:       "KCV-ID101",
						Status:   types.StatusFailure,
						Severity: "MEDIUM",
					},
				},
			},
		},
	}
)

func TestReport_consolidate(t *testing.T) {
	tests := []struct {
		name             string
		report           Report
		expectedFindings map[string]Resource
	}{
		{
			name: "report with both misconfigs and vulnerabilities",
			report: Report{
				Vulnerabilities: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
				},
				Misconfigurations: []Resource{
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":   deployOrionWithBothVulnsAndMisconfigs,
				"default/cronjob/hello":  cronjobHelloWithVulns,
				"default/pod/prometheus": podPrometheusWithMisconfigs,
			},
		},
		{
			name: "report with only misconfigurations",
			report: Report{
				Misconfigurations: []Resource{
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":   deployOrionWithMisconfigs,
				"default/pod/prometheus": podPrometheusWithMisconfigs,
			},
		},
		{
			name: "report with only vulnerabilities",
			report: Report{
				Vulnerabilities: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
				},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":  deployOrionWithVulns,
				"default/cronjob/hello": cronjobHelloWithVulns,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consolidateReport := tt.report.consolidate()
			for _, f := range consolidateReport.Findings {
				key := f.fullname()

				expected, found := tt.expectedFindings[key]
				if !found {
					t.Errorf("key not found: %s", key)
				}

				assert.Equal(t, expected, f)
			}
		})
	}
}

func TestResource_fullname(t *testing.T) {
	tests := []struct {
		expected string
		resource Resource
	}{
		{
			"default/deploy/orion",
			deployOrionWithBothVulnsAndMisconfigs,
		},
		{
			"default/deploy/orion",
			deployOrionWithMisconfigs,
		},
		{
			"default/cronjob/hello",
			cronjobHelloWithVulns,
		},
		{
			"default/pod/prometheus",
			podPrometheusWithMisconfigs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.resource.fullname())
		})
	}
}

func TestResourceFailed(t *testing.T) {
	tests := []struct {
		name     string
		report   Report
		expected bool
	}{
		{
			name: "report with both misconfigs and vulnerabilities",
			report: Report{
				Vulnerabilities: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
				},
				Misconfigurations: []Resource{
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expected: true,
		},
		{
			name: "report with only misconfigurations",
			report: Report{
				Misconfigurations: []Resource{
					deployOrionWithMisconfigs,
					podPrometheusWithMisconfigs,
				},
			},
			expected: true,
		},
		{
			name: "report with only vulnerabilities",
			report: Report{
				Vulnerabilities: []Resource{
					deployOrionWithVulns,
					cronjobHelloWithVulns,
				},
			},
			expected: true,
		},
		{
			name:     "report without vulnerabilities and misconfigurations",
			report:   Report{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.report.Failed())
		})
	}
}

func Test_rbacResource(t *testing.T) {
	tests := []struct {
		name      string
		misConfig Resource
		want      bool
	}{
		{
			name:      "rbac Role resources",
			misConfig: Resource{Kind: "Role"},
			want:      true,
		},
		{
			name:      "rbac ClusterRole resources",
			misConfig: Resource{Kind: "ClusterRole"},
			want:      true,
		},
		{
			name:      "rbac RoleBinding resources",
			misConfig: Resource{Kind: "RoleBinding"},
			want:      true,
		},
		{
			name:      "rbac ClusterRoleBinding resources",
			misConfig: Resource{Kind: "ClusterRoleBinding"},
			want:      true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := rbacResource(test.misConfig)
			assert.Equal(t, test.want, got)
		})
	}
}

func Test_separateMisconfigReports(t *testing.T) {
	k8sReport := Report{
		Misconfigurations: []Resource{
			{Kind: "Role"},
			{Kind: "Deployment"},
			{Kind: "StatefulSet"},
			{
				Kind:      "Pod",
				Namespace: "kube-system",
				Results: []types.Result{
					{Misconfigurations: []types.DetectedMisconfiguration{{ID: "KCV-0001"}}},
					{Misconfigurations: []types.DetectedMisconfiguration{{ID: "KSV-0001"}}},
				},
			},
		},
	}

	tests := []struct {
		name            string
		k8sReport       Report
		scanners        types.Scanners
		components      []string
		expectedReports []Report
	}{
		{
			name:      "Config, Rbac, and Infra Reports",
			k8sReport: k8sReport,
			scanners: types.Scanners{
				types.MisconfigScanner,
				types.RBACScanner,
			},
			components: []string{
				workloadComponent,
				infraComponent,
			},
			expectedReports: []Report{
				// the order matter for the test
				{
					Misconfigurations: []Resource{
						{Kind: "Deployment"},
						{Kind: "StatefulSet"},
						{Kind: "Pod"},
					},
				},
				{Misconfigurations: []Resource{{Kind: "Role"}}},
				{Misconfigurations: []Resource{{Kind: "Pod"}}},
			},
		},
		{
			name:      "Config and Infra for the same resource",
			k8sReport: k8sReport,
			scanners:  types.Scanners{types.MisconfigScanner},
			components: []string{
				workloadComponent,
				infraComponent,
			},
			expectedReports: []Report{
				// the order matter for the test
				{
					Misconfigurations: []Resource{
						{Kind: "Deployment"},
						{Kind: "StatefulSet"},
						{Kind: "Pod"},
					},
				},
				{Misconfigurations: []Resource{{Kind: "Pod"}}},
			},
		},
		{
			name:      "Role Report Only",
			k8sReport: k8sReport,
			scanners:  types.Scanners{types.RBACScanner},
			expectedReports: []Report{
				{Misconfigurations: []Resource{{Kind: "Role"}}},
			},
		},
		{
			name:       "Config Report Only",
			k8sReport:  k8sReport,
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{workloadComponent},
			expectedReports: []Report{
				{
					Misconfigurations: []Resource{
						{Kind: "Deployment"},
						{Kind: "StatefulSet"},
						{Kind: "Pod"},
					},
				},
			},
		},
		{
			name:       "Infra Report Only",
			k8sReport:  k8sReport,
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{infraComponent},
			expectedReports: []Report{
				{Misconfigurations: []Resource{{Kind: "Pod"}}},
			},
		},

		// TODO: add vuln only
		// TODO: add secret only
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reports := separateMisconfigReports(tt.k8sReport, tt.scanners, tt.components)
			assert.Equal(t, len(tt.expectedReports), len(reports))

			for i := range reports {
				assert.Equal(t, len(tt.expectedReports[i].Misconfigurations), len(reports[i].report.Misconfigurations))
				for j, m := range tt.expectedReports[i].Misconfigurations {
					assert.Equal(t, m.Kind, reports[i].report.Misconfigurations[j].Kind)
				}
			}
		})
	}
}

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
		report         Report
		opt            Option
		scanners       types.Scanners
		components     []string
		severities     []dbTypes.Severity
		expectedOutput string
	}{
		{
			name: "Only config, all serverities",
			report: Report{
				ClusterName:       "test",
				Misconfigurations: []Resource{deployOrionWithMisconfigs},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{workloadComponent},
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
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Only vuln, all serverities",
			report: Report{
				ClusterName:     "test",
				Vulnerabilities: []Resource{deployOrionWithVulns},
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
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "Only rbac, all serverities",
			report: Report{
				ClusterName:       "test",
				Misconfigurations: []Resource{roleWithMisconfig},
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
			report: Report{
				ClusterName:     "test",
				Vulnerabilities: []Resource{deployLuaWithSecrets},
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
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, only infra and serverities",
			report: Report{
				ClusterName:       "test",
				Misconfigurations: []Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners:   types.Scanners{types.MisconfigScanner},
			components: []string{infraComponent},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Infra Assessment
┌─────────────┬────────────────────┬─────────────────────────────┐
│  Namespace  │      Resource      │ Kubernetes Infra Assessment │
│             │                    ├─────┬─────┬─────┬─────┬─────┤
│             │                    │  C  │  H  │  M  │  L  │  U  │
├─────────────┼────────────────────┼─────┼─────┼─────┼─────┼─────┤
│ kube-system │ Pod/kube-apiserver │     │     │ 1   │ 1   │     │
└─────────────┴────────────────────┴─────┴─────┴─────┴─────┴─────┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, vuln,config,secret and serverities",
			report: Report{
				ClusterName:       "test",
				Misconfigurations: []Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners: types.Scanners{
				types.VulnerabilityScanner,
				types.MisconfigScanner,
				types.SecretScanner,
			},
			components: []string{workloadComponent},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌─────────────┬────────────────────┬───────────────────┬───────────────────┬───────────────────┐
│  Namespace  │      Resource      │  Vulnerabilities  │ Misconfigurations │      Secrets      │
│             │                    ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│             │                    │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
├─────────────┼────────────────────┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
│ kube-system │ Pod/kube-apiserver │   │   │   │   │   │   │ 1 │ 1 │ 1 │   │   │   │   │   │   │
└─────────────┴────────────────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
		{
			name: "apiserver, all scanners and serverities",
			report: Report{
				ClusterName:       "test",
				Misconfigurations: []Resource{apiseverPodWithMisconfigAndInfra},
			},
			scanners: types.Scanners{
				types.MisconfigScanner,
				types.VulnerabilityScanner,
				types.RBACScanner,
				types.SecretScanner,
			},
			components: []string{
				workloadComponent,
				infraComponent,
			},
			severities: allSeverities,
			expectedOutput: `Summary Report for test
=======================

Workload Assessment
┌─────────────┬────────────────────┬───────────────────┬───────────────────┬───────────────────┐
│  Namespace  │      Resource      │  Vulnerabilities  │ Misconfigurations │      Secrets      │
│             │                    ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│             │                    │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
├─────────────┼────────────────────┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
│ kube-system │ Pod/kube-apiserver │   │   │   │   │   │   │ 1 │ 1 │ 1 │   │   │   │   │   │   │
└─────────────┴────────────────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌─────────────┬────────────────────┬─────────────────────────────┐
│  Namespace  │      Resource      │ Kubernetes Infra Assessment │
│             │                    ├─────┬─────┬─────┬─────┬─────┤
│             │                    │  C  │  H  │  M  │  L  │  U  │
├─────────────┼────────────────────┼─────┼─────┼─────┼─────┼─────┤
│ kube-system │ Pod/kube-apiserver │     │     │ 1   │ 1   │     │
└─────────────┴────────────────────┴─────┴─────┴─────┴─────┴─────┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := bytes.Buffer{}

			opt := Option{
				Format:     "table",
				Report:     "summary",
				Output:     &output,
				Scanners:   tc.scanners,
				Severities: tc.severities,
				Components: tc.components,
			}

			Write(tc.report, opt)

			assert.Equal(t, tc.expectedOutput, stripAnsi(output.String()), tc.name)
		})
	}

}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var ansiRegexp = regexp.MustCompile(ansi)

func stripAnsi(str string) string {
	return strings.TrimSpace(ansiRegexp.ReplaceAllString(str, ""))
}
