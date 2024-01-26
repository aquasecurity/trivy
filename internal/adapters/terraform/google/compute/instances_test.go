package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
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
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("test", defsecTypes.NewTestMetadata()),
					NetworkInterfaces: []compute.NetworkInterface{
						{
							Metadata:    defsecTypes.NewTestMetadata(),
							HasPublicIP: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							NATIP:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   defsecTypes.NewTestMetadata(),
						SecureBootEnabled:          defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						VTPMEnabled:                defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: defsecTypes.NewTestMetadata(),
						Email:    defsecTypes.String("", defsecTypes.NewTestMetadata()),
						Scopes: []defsecTypes.StringValue{
							defsecTypes.String("cloud-platform", defsecTypes.NewTestMetadata()),
						},
						IsDefault: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
					CanIPForward:                defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					OSLoginEnabled:              defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					EnableSerialPort:            defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),

					BootDisks: []compute.Disk{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("boot-disk", defsecTypes.NewTestMetadata()),
							Encryption: compute.DiskEncryption{
								Metadata:   defsecTypes.NewTestMetadata(),
								KMSKeyLink: defsecTypes.String("something", defsecTypes.NewTestMetadata()),
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
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   defsecTypes.NewTestMetadata(),
						SecureBootEnabled:          defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						VTPMEnabled:                defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  defsecTypes.NewTestMetadata(),
						Email:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
						IsDefault: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
					CanIPForward:                defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					OSLoginEnabled:              defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					EnableSerialPort:            defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   defsecTypes.NewTestMetadata(),
						SecureBootEnabled:          defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						VTPMEnabled:                defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  defsecTypes.NewTestMetadata(),
						Email:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
						IsDefault: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
					CanIPForward:                defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					OSLoginEnabled:              defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					EnableSerialPort:            defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
