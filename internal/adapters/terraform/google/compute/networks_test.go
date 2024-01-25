package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/google/compute"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptNetworks(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Network
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_subnetwork" "example" {
				name          = "test-subnetwork"
				network       = google_compute_network.example.id
				log_config {
				  aggregation_interval = "INTERVAL_10_MIN"
				  flow_sampling        = 0.5
				  metadata             = "INCLUDE_ALL_METADATA"
				}
			  }

			  resource "google_compute_network" "example" {
				name                    = "test-network"
				auto_create_subnetworks = false
			  }

			  resource "google_compute_firewall" "example" {
				name        = "my-firewall-rule"
				network = google_compute_network.example.name
				source_ranges = ["1.2.3.4/32"]
				allow {
				  protocol = "icmp"
				  ports     = ["80", "8080"]
				}
			  }
`,
			expected: []compute.Network{
				{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Firewall: &compute.Firewall{
						Metadata: defsecTypes.NewTestMisconfigMetadata(),
						Name:     defsecTypes.String("my-firewall-rule", defsecTypes.NewTestMisconfigMetadata()),
						IngressRules: []compute.IngressRule{
							{
								Metadata: defsecTypes.NewTestMisconfigMetadata(),
								FirewallRule: compute.FirewallRule{
									Metadata: defsecTypes.NewTestMisconfigMetadata(),
									IsAllow:  defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
									Protocol: defsecTypes.String("icmp", defsecTypes.NewTestMisconfigMetadata()),
									Enforced: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
									Ports: []defsecTypes.IntValue{
										defsecTypes.Int(80, defsecTypes.NewTestMisconfigMetadata()),
										defsecTypes.Int(8080, defsecTypes.NewTestMisconfigMetadata()),
									},
								},
								SourceRanges: []defsecTypes.StringValue{
									defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMisconfigMetadata()),
								},
							},
						},
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       defsecTypes.NewTestMisconfigMetadata(),
							Name:           defsecTypes.String("test-subnetwork", defsecTypes.NewTestMisconfigMetadata()),
							EnableFlowLogs: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
							Purpose:        defsecTypes.StringDefault("PRIVATE_RFC_1918", defsecTypes.NewTestMisconfigMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_subnetwork" "example" {
				network = google_compute_network.example.id
				purpose = "REGIONAL_MANAGED_PROXY"
			  }

			  resource "google_compute_network" "example" {
			  }

			  resource "google_compute_firewall" "example" {
				network = google_compute_network.example.name
			}
`,
			expected: []compute.Network{
				{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Firewall: &compute.Firewall{
						Metadata: defsecTypes.NewTestMisconfigMetadata(),
						Name:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       defsecTypes.NewTestMisconfigMetadata(),
							Name:           defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
							EnableFlowLogs: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
							Purpose:        defsecTypes.String("REGIONAL_MANAGED_PROXY", defsecTypes.NewTestMisconfigMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNetworks(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
