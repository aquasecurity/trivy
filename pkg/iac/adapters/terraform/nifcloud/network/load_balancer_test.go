package network

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptLoadBalancers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.LoadBalancer
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_load_balancer" "example" {
			    load_balancer_name = "example"
			    load_balancer_port = 80
			    ssl_policy_id      = "example-ssl-policy-id"
			}

			resource "nifcloud_load_balancer_listener" "example" {
			    load_balancer_name = nifcloud_load_balancer.example.load_balancer_name
			    load_balancer_port = 443
			    ssl_policy_name    = "example-ssl-policy-name"
			}

`,
			expected: []network.LoadBalancer{{
				Listeners: []network.LoadBalancerListener{
					{
						TLSPolicy: iacTypes.StringTest("example-ssl-policy-id"),
						Protocol:  iacTypes.StringTest("HTTP"),
					},
					{
						TLSPolicy: iacTypes.StringTest("example-ssl-policy-name"),
						Protocol:  iacTypes.StringTest("HTTPS"),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_load_balancer" "example" {
			}
`,

			expected: []network.LoadBalancer{{
				Listeners: []network.LoadBalancerListener{{}},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLoadBalancers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
