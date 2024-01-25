package network

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/network"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Listeners: []network.LoadBalancerListener{
					{
						Metadata:  defsecTypes.NewTestMisconfigMetadata(),
						TLSPolicy: defsecTypes.String("example-ssl-policy-id", defsecTypes.NewTestMisconfigMetadata()),
						Protocol:  defsecTypes.String("HTTP", defsecTypes.NewTestMisconfigMetadata()),
					},
					{
						Metadata:  defsecTypes.NewTestMisconfigMetadata(),
						TLSPolicy: defsecTypes.String("example-ssl-policy-name", defsecTypes.NewTestMisconfigMetadata()),
						Protocol:  defsecTypes.String("HTTPS", defsecTypes.NewTestMisconfigMetadata()),
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Listeners: []network.LoadBalancerListener{{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
				}},
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
