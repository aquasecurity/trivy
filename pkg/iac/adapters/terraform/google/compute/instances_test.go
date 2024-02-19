package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
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
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test", iacTypes.NewTestMetadata()),
					NetworkInterfaces: []compute.NetworkInterface{
						{
							Metadata:    iacTypes.NewTestMetadata(),
							HasPublicIP: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							NATIP:       iacTypes.String("", iacTypes.NewTestMetadata()),
						},
					},
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   iacTypes.NewTestMetadata(),
						SecureBootEnabled:          iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						VTPMEnabled:                iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: iacTypes.NewTestMetadata(),
						Email:    iacTypes.String("", iacTypes.NewTestMetadata()),
						Scopes: []iacTypes.StringValue{
							iacTypes.String("cloud-platform", iacTypes.NewTestMetadata()),
						},
						IsDefault: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					},
					CanIPForward:                iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					OSLoginEnabled:              iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					EnableSerialPort:            iacTypes.Bool(true, iacTypes.NewTestMetadata()),

					BootDisks: []compute.Disk{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("boot-disk", iacTypes.NewTestMetadata()),
							Encryption: compute.DiskEncryption{
								Metadata:   iacTypes.NewTestMetadata(),
								KMSKeyLink: iacTypes.String("something", iacTypes.NewTestMetadata()),
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
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("", iacTypes.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   iacTypes.NewTestMetadata(),
						SecureBootEnabled:          iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						VTPMEnabled:                iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  iacTypes.NewTestMetadata(),
						Email:     iacTypes.String("", iacTypes.NewTestMetadata()),
						IsDefault: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					},
					CanIPForward:                iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					OSLoginEnabled:              iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					EnableSerialPort:            iacTypes.Bool(false, iacTypes.NewTestMetadata()),
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
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("", iacTypes.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   iacTypes.NewTestMetadata(),
						SecureBootEnabled:          iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						VTPMEnabled:                iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  iacTypes.NewTestMetadata(),
						Email:     iacTypes.String("", iacTypes.NewTestMetadata()),
						IsDefault: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					},
					CanIPForward:                iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					OSLoginEnabled:              iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					EnableSerialPort:            iacTypes.Bool(false, iacTypes.NewTestMetadata()),
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
