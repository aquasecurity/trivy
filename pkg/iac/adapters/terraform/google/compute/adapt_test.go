package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLines(t *testing.T) {
	src := `
	resource "google_compute_disk" "example" {
		name  = "disk #1"
	
		disk_encryption_key {
		  kms_key_self_link = ""
		  raw_key="b2ggbm8gdGhpcyBpcyBiYWQ"
		}
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
			email  = "email"
			scopes = ["cloud-platform"]
		}
		can_ip_forward = true

		metadata = {
			enable-oslogin = false
			block-project-ssh-keys = true
			serial-port-enable = true
		}
	}
	 
	resource "google_compute_project_metadata" "example" {
		metadata = {
		  enable-oslogin = true
		}
	  }

	  resource "google_compute_network" "example" {
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

	  resource "google_compute_subnetwork" "example" {
		name          = "test-subnetwork"
		network       = google_compute_network.example.id
		log_config {
		  aggregation_interval = "INTERVAL_10_MIN"
		  flow_sampling        = 0.5
		  metadata             = "INCLUDE_ALL_METADATA"
		}
	  }

	  resource "google_compute_ssl_policy" "example" {
		name    = "production-ssl-policy"
		profile = "MODERN"
		min_tls_version = "TLS_1_2"
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Disks, 1)
	require.Len(t, adapted.Instances, 1)
	require.Len(t, adapted.Networks, 1)
	require.Len(t, adapted.SSLPolicies, 1)

	disk := adapted.Disks[0]
	instance := adapted.Instances[0]
	network := adapted.Networks[0]
	ssslPolicy := adapted.SSLPolicies[0]
	metadata := adapted.ProjectMetadata

	assert.Equal(t, 2, disk.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, disk.Metadata.Range().GetEndLine())

	assert.Equal(t, 5, disk.Encryption.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, disk.Encryption.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, disk.Encryption.KMSKeyLink.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, disk.Encryption.KMSKeyLink.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, disk.Encryption.RawKey.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, disk.Encryption.RawKey.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, instance.Metadata.Range().GetStartLine())
	assert.Equal(t, 43, instance.Metadata.Range().GetEndLine())

	assert.Equal(t, 12, instance.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, instance.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, instance.BootDisks[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 17, instance.BootDisks[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 15, instance.BootDisks[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, instance.BootDisks[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, instance.BootDisks[0].Encryption.KMSKeyLink.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, instance.BootDisks[0].Encryption.KMSKeyLink.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, instance.ShieldedVM.Metadata.Range().GetStartLine())
	assert.Equal(t, 23, instance.ShieldedVM.Metadata.Range().GetEndLine())

	assert.Equal(t, 20, instance.ShieldedVM.IntegrityMonitoringEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, instance.ShieldedVM.IntegrityMonitoringEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, instance.ShieldedVM.VTPMEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, instance.ShieldedVM.VTPMEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, instance.ShieldedVM.SecureBootEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, instance.ShieldedVM.SecureBootEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, instance.ServiceAccount.Metadata.Range().GetStartLine())
	assert.Equal(t, 43, instance.ServiceAccount.Metadata.Range().GetEndLine())

	assert.Equal(t, 33, instance.ServiceAccount.Email.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 33, instance.ServiceAccount.Email.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 34, instance.ServiceAccount.Scopes[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, instance.ServiceAccount.Scopes[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 36, instance.CanIPForward.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 36, instance.CanIPForward.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, instance.OSLoginEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 42, instance.OSLoginEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, instance.EnableProjectSSHKeyBlocking.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 42, instance.EnableProjectSSHKeyBlocking.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, instance.EnableSerialPort.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 42, instance.EnableSerialPort.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 45, metadata.Metadata.Range().GetStartLine())
	assert.Equal(t, 49, metadata.Metadata.Range().GetEndLine())

	assert.Equal(t, 51, network.Metadata.Range().GetStartLine())
	assert.Equal(t, 52, network.Metadata.Range().GetEndLine())

	assert.Equal(t, 54, network.Firewall.Metadata.Range().GetStartLine())
	assert.Equal(t, 62, network.Firewall.Metadata.Range().GetEndLine())

	assert.Equal(t, 55, network.Firewall.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 55, network.Firewall.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 54, network.Firewall.IngressRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 62, network.Firewall.IngressRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 57, network.Firewall.IngressRules[0].SourceRanges[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 57, network.Firewall.IngressRules[0].SourceRanges[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 59, network.Firewall.IngressRules[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 59, network.Firewall.IngressRules[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 60, network.Firewall.IngressRules[0].Ports[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 60, network.Firewall.IngressRules[0].Ports[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 64, network.Subnetworks[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 72, network.Subnetworks[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 65, network.Subnetworks[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 65, network.Subnetworks[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 67, network.Subnetworks[0].EnableFlowLogs.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 71, network.Subnetworks[0].EnableFlowLogs.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 74, ssslPolicy.Metadata.Range().GetStartLine())
	assert.Equal(t, 78, ssslPolicy.Metadata.Range().GetEndLine())

	assert.Equal(t, 75, ssslPolicy.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 75, ssslPolicy.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 76, ssslPolicy.Profile.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 76, ssslPolicy.Profile.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 77, ssslPolicy.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 77, ssslPolicy.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

}
