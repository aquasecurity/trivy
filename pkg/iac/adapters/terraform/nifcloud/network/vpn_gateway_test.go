package network

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptVpnGateways(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.VpnGateway
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_vpn_gateway" "example" {
				security_group  = "example-security-group"
			}
`,
			expected: []network.VpnGateway{{
				Metadata:      defsecTypes.NewTestMetadata(),
				SecurityGroup: defsecTypes.String("example-security-group", defsecTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_vpn_gateway" "example" {
			}
`,

			expected: []network.VpnGateway{{
				Metadata:      defsecTypes.NewTestMetadata(),
				SecurityGroup: defsecTypes.String("", defsecTypes.NewTestMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptVpnGateways(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
