package rdb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/rdb"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata:                  defsecTypes.NewTestMetadata(),
				BackupRetentionPeriodDays: defsecTypes.Int(2, defsecTypes.NewTestMetadata()),
				Engine:                    defsecTypes.String("MySQL", defsecTypes.NewTestMetadata()),
				EngineVersion:             defsecTypes.String("5.7.15", defsecTypes.NewTestMetadata()),
				NetworkID:                 defsecTypes.String("example-network", defsecTypes.NewTestMetadata()),
				PublicAccess:              defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_db_instance" "example" {
			}
`,

			expected: []rdb.DBInstance{{
				Metadata:                  defsecTypes.NewTestMetadata(),
				BackupRetentionPeriodDays: defsecTypes.Int(0, defsecTypes.NewTestMetadata()),
				Engine:                    defsecTypes.String("", defsecTypes.NewTestMetadata()),
				EngineVersion:             defsecTypes.String("", defsecTypes.NewTestMetadata()),
				NetworkID:                 defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMetadata()),
				PublicAccess:              defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
