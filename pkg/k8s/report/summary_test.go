package report

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReport_ColumnHeading(t *testing.T) {
	allScanners := types.Scanners{
		types.VulnerabilityScanner,
		types.MisconfigScanner,
		types.SecretScanner,
		types.RBACScanner,
	}

	tests := []struct {
		name             string
		scanners         types.Scanners
		components       []string
		availableColumns []string
		want             []string
	}{
		{
			name:             "filter workload columns",
			scanners:         allScanners,
			availableColumns: WorkloadColumns(),
			components: []string{
				workloadComponent,
				infraComponent,
			},
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				VulnerabilitiesColumn,
				MisconfigurationsColumn,
				SecretsColumn,
			},
		},
		{
			name:             "filter rbac columns",
			scanners:         allScanners,
			components:       []string{},
			availableColumns: RoleColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				RbacAssessmentColumn,
			},
		},
		{
			name:     "filter infra columns",
			scanners: allScanners,
			components: []string{
				workloadComponent,
				infraComponent,
			},
			availableColumns: InfraColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				InfraAssessmentColumn,
			},
		},
		{
			name:     "config column only",
			scanners: types.Scanners{types.MisconfigScanner},
			components: []string{
				workloadComponent,
				infraComponent,
			},
			availableColumns: WorkloadColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				MisconfigurationsColumn,
			},
		},
		{
			name:             "secret column only",
			scanners:         types.Scanners{types.SecretScanner},
			components:       []string{},
			availableColumns: WorkloadColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				SecretsColumn,
			},
		},
		{
			name:             "vuln column only",
			scanners:         types.Scanners{types.VulnerabilityScanner},
			components:       []string{},
			availableColumns: WorkloadColumns(),
			want: []string{
				NamespaceColumn,
				ResourceColumn,
				VulnerabilitiesColumn,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			column := ColumnHeading(tt.scanners, tt.components, tt.availableColumns)
			if !assert.Equal(t, column, tt.want) {
				t.Error(fmt.Errorf("TestReport_ColumnHeading want %v got %v", tt.want, column))
			}
		})
	}
}
