package computing

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata:    defsecTypes.NewTestMetadata(),
				Description: defsecTypes.String("memo", defsecTypes.NewTestMetadata()),
				IngressRules: []computing.SecurityGroupRule{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						CIDR:        defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMetadata()),
						Description: defsecTypes.String("memo", defsecTypes.NewTestMetadata()),
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
				Metadata:    defsecTypes.NewTestMetadata(),
				Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				IngressRules: []computing.SecurityGroupRule{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						CIDR:        defsecTypes.String("", defsecTypes.NewTestMetadata()),
						Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
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
