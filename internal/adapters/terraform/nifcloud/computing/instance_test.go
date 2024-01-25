package computing

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/computing"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata:      defsecTypes.NewTestMisconfigMetadata(),
				SecurityGroup: defsecTypes.String("example-security-group", defsecTypes.NewTestMisconfigMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
					{
						Metadata:  defsecTypes.NewTestMisconfigMetadata(),
						NetworkID: defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMisconfigMetadata()),
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
				Metadata:      defsecTypes.NewTestMisconfigMetadata(),
				SecurityGroup: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
				NetworkInterfaces: []computing.NetworkInterface{
					{
						Metadata:  defsecTypes.NewTestMisconfigMetadata(),
						NetworkID: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
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
