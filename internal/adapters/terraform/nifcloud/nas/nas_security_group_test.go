package nas

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/nas"

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
				Metadata:    defsecTypes.NewTestMisconfigMetadata(),
				Description: defsecTypes.String("memo", defsecTypes.NewTestMisconfigMetadata()),
				CIDRs: []defsecTypes.StringValue{
					defsecTypes.String("0.0.0.0/0", defsecTypes.NewTestMisconfigMetadata()),
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
				Metadata:    defsecTypes.NewTestMisconfigMetadata(),
				Description: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
				CIDRs: []defsecTypes.StringValue{
					defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
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
