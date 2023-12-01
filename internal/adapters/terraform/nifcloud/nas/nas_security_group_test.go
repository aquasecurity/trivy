package nas

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/nas"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptNASSecurityGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []nas.NASSecurityGroup
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_nas_security_group" "example" {
				description = "memo"

				rule {
				  cidr_ip = "0.0.0.0/0"
				}
			}
`,
			expected: []nas.NASSecurityGroup{{
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
			resource "nifcloud_nas_security_group" "example" {
				rule {
				}
			}
`,

			expected: []nas.NASSecurityGroup{{
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
			adapted := adaptNASSecurityGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
