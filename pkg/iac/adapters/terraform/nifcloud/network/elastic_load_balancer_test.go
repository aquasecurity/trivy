package network

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
				NetworkInterfaces: []network.NetworkInterface{
					{
						NetworkID: iacTypes.StringTest("net-COMMON_PRIVATE"),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{
					{
						Protocol: iacTypes.StringTest("HTTP"),
					},
					{
						Protocol: iacTypes.StringTest("HTTPS"),
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
				NetworkInterfaces: []network.NetworkInterface{
					{
						IsVipNetwork: iacTypes.BoolTest(true),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{{}},
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
