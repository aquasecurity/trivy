package computing

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptSecurityGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []computing.SecurityGroup
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_security_group" "example" {
				group_name = "example"
				description = "memo"
			}
			
			resource "nifcloud_security_group_rule" "example" {
				type                 = "IN"
				security_group_names = [nifcloud_security_group.example.group_name]
				from_port            = 22
				to_port              = 22
				protocol             = "TCP"
				description          = "memo"
				cidr_ip              = "1.2.3.4/32"
			}
`,
			expected: []computing.SecurityGroup{{
				Description: iacTypes.StringTest("memo"),
				IngressRules: []computing.SecurityGroupRule{
					{
						CIDR:        iacTypes.StringTest("1.2.3.4/32"),
						Description: iacTypes.StringTest("memo"),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_security_group" "example" {
			}
			
			resource "nifcloud_security_group_rule" "example" {
				type                 = "IN"
				security_group_names = [nifcloud_security_group.example.group_name]
			}

`,

			expected: []computing.SecurityGroup{{
				IngressRules: []computing.SecurityGroupRule{
					{},
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("nifcloud_security_group_rule")}
			adapted := sgAdapter.adaptSecurityGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
