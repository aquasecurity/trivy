package commands

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/stretchr/testify/assert"
)

func Test_rbacResource(t *testing.T) {
	tests := []struct {
		name      string
		misConfig report.Resource
		want      bool
	}{
		{
			name:      "rbac Role resources",
			misConfig: report.Resource{Kind: "Role"},
			want:      true,
		},
		{
			name:      "rbac ClusterRole resources",
			misConfig: report.Resource{Kind: "ClusterRole"},
			want:      true,
		},
		{
			name:      "rbac RoleBinding resources",
			misConfig: report.Resource{Kind: "RoleBinding"},
			want:      true,
		},
		{
			name:      "rbac ClusterRoleBinding resources",
			misConfig: report.Resource{Kind: "ClusterRoleBinding"},
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

func Test_separateMisConfigRoleAssessment(t *testing.T) {
	tests := []struct {
		name                string
		k8sReport           report.Report
		rp                  option.ReportOption
		wantRbacReport      report.Report
		wantMisConfigReport report.Report
	}{
		{
			name:                "Role and Deployment Reports",
			k8sReport:           report.Report{Misconfigurations: []report.Resource{{Kind: "Role"}, {Kind: "Deployment"}}},
			rp:                  option.ReportOption{SecurityChecks: []string{"config", "rbac"}},
			wantRbacReport:      report.Report{Misconfigurations: []report.Resource{{Kind: "Role"}}},
			wantMisConfigReport: report.Report{Misconfigurations: []report.Resource{{Kind: "Deployment"}}},
		},
		{
			name:                "Role Report Only",
			k8sReport:           report.Report{Misconfigurations: []report.Resource{{Kind: "Role"}, {Kind: "Deployment"}}},
			rp:                  option.ReportOption{SecurityChecks: []string{"rbac"}},
			wantRbacReport:      report.Report{Misconfigurations: []report.Resource{{Kind: "Role"}}},
			wantMisConfigReport: report.Report{Misconfigurations: []report.Resource{}},
		},
		{
			name:                "Deployment Report Only",
			k8sReport:           report.Report{Misconfigurations: []report.Resource{{Kind: "Role"}, {Kind: "Deployment"}}},
			rp:                  option.ReportOption{SecurityChecks: []string{"config"}},
			wantRbacReport:      report.Report{Misconfigurations: []report.Resource{}},
			wantMisConfigReport: report.Report{Misconfigurations: []report.Resource{{Kind: "Deployment"}}},
		},
		{
			name:                "No Deployment & No Role Reports",
			k8sReport:           report.Report{Misconfigurations: []report.Resource{{Kind: "Role"}, {Kind: "Deployment"}}},
			rp:                  option.ReportOption{SecurityChecks: []string{"vuln"}},
			wantRbacReport:      report.Report{Misconfigurations: []report.Resource{}},
			wantMisConfigReport: report.Report{Misconfigurations: []report.Resource{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			misConfig, rbac := separateMisConfigRoleAssessment(tt.k8sReport, tt.rp)
			assert.Equal(t, len(tt.wantMisConfigReport.Misconfigurations), len(misConfig.Misconfigurations))
			assert.Equal(t, len(tt.wantRbacReport.Misconfigurations), len(rbac.Misconfigurations))
		})
	}
}
