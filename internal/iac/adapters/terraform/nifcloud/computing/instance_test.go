package computing

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []computing.Instance
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_instance" "my_example" {
				security_group  = "example-security-group"
				network_interface  {
					network_id    = "net-COMMON_PRIVATE"
				}
			}
`,
			expected: []computing.Instance{{
				Metadata:      iacTypes.NewTestMetadata(),
				SecurityGroup: iacTypes.String("example-security-group", iacTypes.NewTestMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
					{
						Metadata:  iacTypes.NewTestMetadata(),
						NetworkID: iacTypes.String("net-COMMON_PRIVATE", iacTypes.NewTestMetadata()),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_instance" "my_example" {
				network_interface  {
				}
			}
`,

			expected: []computing.Instance{{
				Metadata:      iacTypes.NewTestMetadata(),
				SecurityGroup: iacTypes.String("", iacTypes.NewTestMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
					{
						Metadata:  iacTypes.NewTestMetadata(),
						NetworkID: iacTypes.String("", iacTypes.NewTestMetadata()),
					},
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
