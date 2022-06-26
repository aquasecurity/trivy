package report

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/commands/option"
)

func TestReport_ColumnHeading(t *testing.T) {
	tests := []struct {
		name             string
		rp               option.ReportOption
		availableColumns []string
		want             []string
	}{
		{
			name:             "all workload columns",
			rp:               option.ReportOption{SecurityChecks: []string{"vuln", "config", "secret", "rbac"}},
			availableColumns: WorkloadColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, VulnerabilitiesColumn, MisconfigurationsColumn, SecretsColumn},
		},
		{
			name:             "all rbac columns",
			rp:               option.ReportOption{SecurityChecks: []string{"vuln", "config", "secret", "rbac"}},
			availableColumns: RoleColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, RbacAssessmentColumn},
		},
		{
			name:             "config column only",
			rp:               option.ReportOption{SecurityChecks: []string{"config"}},
			availableColumns: WorkloadColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, MisconfigurationsColumn},
		},
		{
			name:             "secret column only",
			rp:               option.ReportOption{SecurityChecks: []string{"secret"}},
			availableColumns: WorkloadColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, SecretsColumn},
		},
		{
			name:             "vuln column only",
			rp:               option.ReportOption{SecurityChecks: []string{"vuln"}},
			availableColumns: WorkloadColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, VulnerabilitiesColumn},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			column := ColumnHeading(tt.rp.SecurityChecks, tt.availableColumns)
			if !assert.Equal(t, column, tt.want) {
				t.Error(fmt.Errorf("TestReport_ColumnHeading want %v got %v", tt.want, column))
			}
		})
	}
}
