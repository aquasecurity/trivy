package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/google/compute"

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
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Name:     defsecTypes.String("test", defsecTypes.NewTestMisconfigMetadata()),
					NetworkInterfaces: []compute.NetworkInterface{
						{
							Metadata:    defsecTypes.NewTestMisconfigMetadata(),
							HasPublicIP: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
							NATIP:       defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
						},
					},
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   defsecTypes.NewTestMisconfigMetadata(),
						SecureBootEnabled:          defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
						IntegrityMonitoringEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
						VTPMEnabled:                defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: defsecTypes.NewTestMisconfigMetadata(),
						Email:    defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
						Scopes: []defsecTypes.StringValue{
							defsecTypes.String("cloud-platform", defsecTypes.NewTestMisconfigMetadata()),
						},
						IsDefault: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					},
					CanIPForward:                defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					OSLoginEnabled:              defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					EnableProjectSSHKeyBlocking: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					EnableSerialPort:            defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),

					BootDisks: []compute.Disk{
						{
							Metadata: defsecTypes.NewTestMisconfigMetadata(),
							Name:     defsecTypes.String("boot-disk", defsecTypes.NewTestMisconfigMetadata()),
							Encryption: compute.DiskEncryption{
								Metadata:   defsecTypes.NewTestMisconfigMetadata(),
								KMSKeyLink: defsecTypes.String("something", defsecTypes.NewTestMisconfigMetadata()),
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
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Name:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   defsecTypes.NewTestMisconfigMetadata(),
						SecureBootEnabled:          defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
						IntegrityMonitoringEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
						VTPMEnabled:                defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  defsecTypes.NewTestMisconfigMetadata(),
						Email:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
						IsDefault: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					},
					CanIPForward:                defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					OSLoginEnabled:              defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					EnableProjectSSHKeyBlocking: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					EnableSerialPort:            defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
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
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Name:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   defsecTypes.NewTestMisconfigMetadata(),
						SecureBootEnabled:          defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
						IntegrityMonitoringEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
						VTPMEnabled:                defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  defsecTypes.NewTestMisconfigMetadata(),
						Email:     defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
						IsDefault: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					},
					CanIPForward:                defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					OSLoginEnabled:              defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					EnableProjectSSHKeyBlocking: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					EnableSerialPort:            defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
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
