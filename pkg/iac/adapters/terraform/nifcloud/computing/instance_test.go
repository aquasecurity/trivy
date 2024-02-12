package computing

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
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
				Metadata:      defsecTypes.NewTestMetadata(),
				SecurityGroup: defsecTypes.String("example-security-group", defsecTypes.NewTestMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						NetworkID: defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMetadata()),
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
				Metadata:      defsecTypes.NewTestMetadata(),
				SecurityGroup: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						NetworkID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
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
