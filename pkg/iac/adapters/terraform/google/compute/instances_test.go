package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Instance
	}{
		{
			name: "defined",
			terraform: `
			resource "google_service_account" "myaccount" {
			  }
		  
			resource "google_compute_instance" "example" {
				name         = "test"
		
				boot_disk {
					device_name = "boot-disk"
					kms_key_self_link = "something"
				  }
			  
				shielded_instance_config {
				  enable_integrity_monitoring = true
				  enable_vtpm = true
				  enable_secure_boot = true
				}

				network_interface {
					network = "default"
				
					access_config {
					}
				  }

				  service_account {
					email  = google_service_account.myaccount.email
					scopes = ["cloud-platform"]
				  }
				  can_ip_forward = true

				  metadata = {
					enable-oslogin = false
					block-project-ssh-keys = true
					serial-port-enable = true
				  }
			  }
`,
			expected: []compute.Instance{
				{
					Name: iacTypes.StringTest("test"),
					NetworkInterfaces: []compute.NetworkInterface{
						{
							HasPublicIP: iacTypes.BoolTest(true),
						},
					},
					ShieldedVM: compute.ShieldedVMConfig{
						SecureBootEnabled:          iacTypes.BoolTest(true),
						IntegrityMonitoringEnabled: iacTypes.BoolTest(true),
						VTPMEnabled:                iacTypes.BoolTest(true),
					},
					ServiceAccount: compute.ServiceAccount{
						Scopes: []iacTypes.StringValue{
							iacTypes.StringTest("cloud-platform"),
						},
					},
					CanIPForward:                iacTypes.BoolTest(true),
					EnableProjectSSHKeyBlocking: iacTypes.BoolTest(true),
					EnableSerialPort:            iacTypes.BoolTest(true),
					BootDisks: []compute.Disk{
						{
							Name: iacTypes.StringTest("boot-disk"),
							Encryption: compute.DiskEncryption{
								KMSKeyLink: iacTypes.StringTest("something"),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_instance" "example" {
			  }
`,
			expected: []compute.Instance{
				{
					ShieldedVM:     compute.ShieldedVMConfig{},
					ServiceAccount: compute.ServiceAccount{},
					OSLoginEnabled: iacTypes.BoolTest(true),
				},
			},
		},
		{
			name: "default service account",
			terraform: `
			resource "google_compute_instance" "example" {
				service_account {}
			}
`,
			expected: []compute.Instance{
				{
					ShieldedVM: compute.ShieldedVMConfig{},
					ServiceAccount: compute.ServiceAccount{
						IsDefault: iacTypes.BoolTest(true),
					},
					OSLoginEnabled: iacTypes.BoolTest(true),
				},
			},
		},
		{
			name: "handles metadata values in various formats",
			terraform: `resource "google_compute_instance" "example" {
	name = "test"

	metadata = {
		enable-oslogin = "True"
		block-project-ssh-keys = 1
		serial-port-enable = "yes"
	}
}`,
			expected: []compute.Instance{
				{
					Name:                        iacTypes.StringTest("test"),
					OSLoginEnabled:              iacTypes.BoolTest(true),
					EnableSerialPort:            iacTypes.BoolTest(true),
					EnableProjectSSHKeyBlocking: iacTypes.BoolTest(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
