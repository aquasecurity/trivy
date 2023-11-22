package network

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/network"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptElasticLoadBalancers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.ElasticLoadBalancer
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_elb" "example" {
                protocol = "HTTP"

				network_interface  {
					network_id     = "net-COMMON_PRIVATE"
					is_vip_network = false
				}
			}

            resource "nifcloud_elb_listener" "example" {
                elb_id   = nifcloud_elb.example.id
                protocol = "HTTPS"
            }
`,
			expected: []network.ElasticLoadBalancer{{
				Metadata: defsecTypes.NewTestMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     defsecTypes.NewTestMetadata(),
						NetworkID:    defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMetadata()),
						IsVipNetwork: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMetadata()),
					},
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Protocol: defsecTypes.String("HTTPS", defsecTypes.NewTestMetadata()),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_elb" "example" {
				network_interface  {
				}
			}
`,

			expected: []network.ElasticLoadBalancer{{
				Metadata: defsecTypes.NewTestMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     defsecTypes.NewTestMetadata(),
						NetworkID:    defsecTypes.String("", defsecTypes.NewTestMetadata()),
						IsVipNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{{
					Metadata: defsecTypes.NewTestMetadata(),
				}},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptElasticLoadBalancers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
