package report

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/stretchr/testify/assert"
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
			want:             []string{NameSpaceColumn, ResourceColumn, VulnerabilitiesColumn, MisconfigurationsColumn, SecretsColumn},
		},
		{
			name:             "all rbac columns",
			rp:               option.ReportOption{SecurityChecks: []string{"vuln", "config", "secret", "rbac"}},
			availableColumns: RoleColumns(),
			want:             []string{NameSpaceColumn, ResourceColumn, RbacAssessmentColumn},
		},
		{
			name:             "config column only",
			rp:               option.ReportOption{SecurityChecks: []string{"config"}},
			availableColumns: WorkloadColumns(),
			want:             []string{NameSpaceColumn, ResourceColumn, MisconfigurationsColumn},
		},
		{
			name:             "secret column only",
			rp:               option.ReportOption{SecurityChecks: []string{"secret"}},
			availableColumns: WorkloadColumns(),
			want:             []string{NameSpaceColumn, ResourceColumn, SecretsColumn},
		},
		{
			name:             "vuln column only",
			rp:               option.ReportOption{SecurityChecks: []string{"secret"}},
			availableColumns: WorkloadColumns(),
			want:             []string{NameSpaceColumn, ResourceColumn, VulnerabilitiesColumn},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			column := ColumnHeading(tt.rp, tt.availableColumns)
			if !assert.Equal(t, column, tt.want) {
				t.Error(fmt.Errorf("TestReport_ColumnHeading want %v got %v", tt.want, column))
			}
		})
	}
}
