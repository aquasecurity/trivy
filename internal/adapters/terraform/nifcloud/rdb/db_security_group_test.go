package rdb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/rdb"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptDBSecurityGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []rdb.DBSecurityGroup
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_db_security_group" "example" {
				description = "memo"

				rule {
				  cidr_ip = "0.0.0.0/0"
				}
			}
`,
			expected: []rdb.DBSecurityGroup{{
				Metadata:    defsecTypes.NewTestMetadata(),
				Description: defsecTypes.String("memo", defsecTypes.NewTestMetadata()),
				CIDRs: []defsecTypes.StringValue{
					defsecTypes.String("0.0.0.0/0", defsecTypes.NewTestMetadata()),
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_db_security_group" "example" {
				rule {
				}
			}
`,

			expected: []rdb.DBSecurityGroup{{
				Metadata:    defsecTypes.NewTestMetadata(),
				Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				CIDRs: []defsecTypes.StringValue{
					defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDBSecurityGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
