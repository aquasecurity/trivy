package nas

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/nas"
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
				Metadata:    iacTypes.NewTestMetadata(),
				Description: iacTypes.String("memo", iacTypes.NewTestMetadata()),
				CIDRs: []iacTypes.StringValue{
					iacTypes.String("0.0.0.0/0", iacTypes.NewTestMetadata()),
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
				Metadata:    iacTypes.NewTestMetadata(),
				Description: iacTypes.String("", iacTypes.NewTestMetadata()),
				CIDRs: []iacTypes.StringValue{
					iacTypes.String("", iacTypes.NewTestMetadata()),
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
