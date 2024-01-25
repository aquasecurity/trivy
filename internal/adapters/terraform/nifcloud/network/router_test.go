package network

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/network"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

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
				Metadata:      defsecTypes.NewTestMisconfigMetadata(),
				SecurityGroup: defsecTypes.String("example-security-group", defsecTypes.NewTestMisconfigMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
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
			resource "nifcloud_router" "example" {
				network_interface  {
				}
			}
`,

			expected: []network.Router{{
				Metadata:      defsecTypes.NewTestMisconfigMetadata(),
				SecurityGroup: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
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
			adapted := adaptRouters(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
