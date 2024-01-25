package network

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/network"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     defsecTypes.NewTestMisconfigMetadata(),
						NetworkID:    defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMisconfigMetadata()),
						IsVipNetwork: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{
					{
						Metadata: defsecTypes.NewTestMisconfigMetadata(),
						Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMisconfigMetadata()),
					},
					{
						Metadata: defsecTypes.NewTestMisconfigMetadata(),
						Protocol: defsecTypes.String("HTTPS", defsecTypes.NewTestMisconfigMetadata()),
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:     defsecTypes.NewTestMisconfigMetadata(),
						NetworkID:    defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
						IsVipNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					},
				},
				Listeners: []network.ElasticLoadBalancerListener{{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
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
