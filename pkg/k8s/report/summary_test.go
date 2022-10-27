package report

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReport_ColumnHeading(t *testing.T) {
	allSecurityChecks := []string{
		types.SecurityCheckVulnerability,
		types.SecurityCheckConfig,
		types.SecurityCheckSecret,
		types.SecurityCheckRbac,
	}

	tests := []struct {
		name             string
		securityChecks   []string
		components       []string
		availableColumns []string
		want             []string
	}{
		{
			name:             "filter workload columns",
			securityChecks:   allSecurityChecks,
			availableColumns: WorkloadColumns(),
			components:       []string{workloadComponent, infraComponent},
			want:             []string{NamespaceColumn, ResourceColumn, VulnerabilitiesColumn, MisconfigurationsColumn, SecretsColumn},
		},
		{
			name:             "filter rbac columns",
			securityChecks:   allSecurityChecks,
			components:       []string{},
			availableColumns: RoleColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, RbacAssessmentColumn},
		},
		{
			name:             "filter infra columns",
			securityChecks:   allSecurityChecks,
			components:       []string{workloadComponent, infraComponent},
			availableColumns: InfraColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, InfraAssessmentColumn},
		},
		{
			name:             "config column only",
			securityChecks:   []string{types.SecurityCheckConfig},
			components:       []string{workloadComponent, infraComponent},
			availableColumns: WorkloadColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, MisconfigurationsColumn},
		},
		{
			name:             "secret column only",
			securityChecks:   []string{types.SecurityCheckSecret},
			components:       []string{},
			availableColumns: WorkloadColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, SecretsColumn},
		},
		{
			name:             "vuln column only",
			securityChecks:   []string{types.SecurityCheckVulnerability},
			components:       []string{},
			availableColumns: WorkloadColumns(),
			want:             []string{NamespaceColumn, ResourceColumn, VulnerabilitiesColumn},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			column := ColumnHeading(tt.securityChecks, tt.components, tt.availableColumns)
			if !assert.Equal(t, column, tt.want) {
				t.Error(fmt.Errorf("TestReport_ColumnHeading want %v got %v", tt.want, column))
			}
		})
	}
}
