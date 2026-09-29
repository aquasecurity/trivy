package rdb

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/rdb"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptDBInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []rdb.DBInstance
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_db_instance" "example" {
				backup_retention_period = 2
				engine                  = "MySQL"
				engine_version          = "5.7.15"
				publicly_accessible     = false
				network_id              = "example-network"
			}
`,
			expected: []rdb.DBInstance{{
				BackupRetentionPeriodDays: iacTypes.IntTest(2),
				Engine:                    iacTypes.StringTest("MySQL"),
				EngineVersion:             iacTypes.StringTest("5.7.15"),
				NetworkID:                 iacTypes.StringTest("example-network"),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_db_instance" "example" {
			}
`,

			expected: []rdb.DBInstance{{
				NetworkID:    iacTypes.StringTest("net-COMMON_PRIVATE"),
				PublicAccess: iacTypes.BoolTest(true),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDBInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
