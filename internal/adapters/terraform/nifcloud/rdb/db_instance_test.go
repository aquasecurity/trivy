package rdb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/rdb"

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
				Metadata:                  defsecTypes.NewTestMisconfigMetadata(),
				BackupRetentionPeriodDays: defsecTypes.Int(2, defsecTypes.NewTestMisconfigMetadata()),
				Engine:                    defsecTypes.String("MySQL", defsecTypes.NewTestMisconfigMetadata()),
				EngineVersion:             defsecTypes.String("5.7.15", defsecTypes.NewTestMisconfigMetadata()),
				NetworkID:                 defsecTypes.String("example-network", defsecTypes.NewTestMisconfigMetadata()),
				PublicAccess:              defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_db_instance" "example" {
			}
`,

			expected: []rdb.DBInstance{{
				Metadata:                  defsecTypes.NewTestMisconfigMetadata(),
				BackupRetentionPeriodDays: defsecTypes.Int(0, defsecTypes.NewTestMisconfigMetadata()),
				Engine:                    defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
				EngineVersion:             defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
				NetworkID:                 defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMisconfigMetadata()),
				PublicAccess:              defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
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
