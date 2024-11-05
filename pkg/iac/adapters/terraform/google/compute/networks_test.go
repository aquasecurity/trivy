package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
				  ports     = ["80", "8080", "9090-9095"]
				}
			  }
`,
			expected: []compute.Network{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: iacTypes.NewTestMetadata(),
						Name:     iacTypes.String("my-firewall-rule", iacTypes.NewTestMetadata()),
						IngressRules: []compute.IngressRule{
							{
								Metadata: iacTypes.NewTestMetadata(),
								FirewallRule: compute.FirewallRule{
									Metadata: iacTypes.NewTestMetadata(),
									IsAllow:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
									Protocol: iacTypes.String("icmp", iacTypes.NewTestMetadata()),
									Enforced: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
									Ports: []compute.PortRange{
										{
											Start: iacTypes.IntTest(80),
											End:   iacTypes.IntTest(80),
										},
										{
											Start: iacTypes.IntTest(8080),
											End:   iacTypes.IntTest(8080),
										},
										{
											Start: iacTypes.IntTest(9090),
											End:   iacTypes.IntTest(9095),
										},
									},
								},
								SourceRanges: []iacTypes.StringValue{
									iacTypes.String("1.2.3.4/32", iacTypes.NewTestMetadata()),
								},
							},
						},
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       iacTypes.NewTestMetadata(),
							Name:           iacTypes.String("test-subnetwork", iacTypes.NewTestMetadata()),
							EnableFlowLogs: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							Purpose:        iacTypes.StringDefault("PRIVATE_RFC_1918", iacTypes.NewTestMetadata()),
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
					Metadata: iacTypes.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: iacTypes.NewTestMetadata(),
						Name:     iacTypes.String("", iacTypes.NewTestMetadata()),
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       iacTypes.NewTestMetadata(),
							Name:           iacTypes.String("", iacTypes.NewTestMetadata()),
							EnableFlowLogs: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							Purpose:        iacTypes.String("REGIONAL_MANAGED_PROXY", iacTypes.NewTestMetadata()),
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
