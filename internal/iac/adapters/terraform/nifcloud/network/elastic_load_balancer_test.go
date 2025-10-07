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
				Metadata: iacTypes.NewTestMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     iacTypes.NewTestMetadata(),
						NetworkID:    iacTypes.String("net-COMMON_PRIVATE", iacTypes.NewTestMetadata()),
						IsVipNetwork: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Protocol: iacTypes.String("HTTP", iacTypes.NewTestMetadata()),
					},
					{
						Metadata: iacTypes.NewTestMetadata(),
						Protocol: iacTypes.String("HTTPS", iacTypes.NewTestMetadata()),
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
				Metadata: iacTypes.NewTestMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     iacTypes.NewTestMetadata(),
						NetworkID:    iacTypes.String("", iacTypes.NewTestMetadata()),
						IsVipNetwork: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{{
					Metadata: iacTypes.NewTestMetadata(),
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
