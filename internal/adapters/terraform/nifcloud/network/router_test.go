package network

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/network"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptRouters(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.Router
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_router" "example" {
				security_group  = "example-security-group"
				network_interface  {
					network_id    = "net-COMMON_PRIVATE"
				}
			}
`,
			expected: []network.Router{{
				Metadata:      defsecTypes.NewTestMetadata(),
				SecurityGroup: defsecTypes.String("example-security-group", defsecTypes.NewTestMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
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
			resource "nifcloud_router" "example" {
				network_interface  {
				}
			}
`,

			expected: []network.Router{{
				Metadata:      defsecTypes.NewTestMetadata(),
				SecurityGroup: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
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
			adapted := adaptRouters(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
