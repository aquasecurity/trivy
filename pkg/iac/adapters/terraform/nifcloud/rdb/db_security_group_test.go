package rdb

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/rdb"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
				Description: iacTypes.StringTest("memo"),
				CIDRs: []iacTypes.StringValue{
					iacTypes.StringTest("0.0.0.0/0"),
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
				CIDRs: []iacTypes.StringValue{
					iacTypes.StringTest(""),
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
