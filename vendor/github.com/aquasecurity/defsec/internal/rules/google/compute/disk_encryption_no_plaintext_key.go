package compute

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckDiskEncryptionRequired = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0037",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "disk-encryption-no-plaintext-key",
		Summary:     "The encryption key used to encrypt a compute disk has been specified in plaintext.",
		Impact:      "The encryption key should be considered compromised as it is not stored securely.",
		Resolution:  "Reference a managed key rather than include the key in raw format.",
		Explanation: `Sensitive values such as raw encryption keys should not be included in your Terraform code, and should be stored securely by a secrets manager.`,
		Links: []string{
			"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformDiskEncryptionNoPlaintextKeyGoodExamples,
			BadExamples:         terraformDiskEncryptionNoPlaintextKeyBadExamples,
			Links:               terraformDiskEncryptionNoPlaintextKeyLinks,
			RemediationMarkdown: terraformDiskEncryptionNoPlaintextKeyRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			for _, disk := range append(instance.BootDisks, instance.AttachedDisks...) {
				if disk.Encryption.RawKey.Len() > 0 {
					results.Add(
						"Instance disk has encryption key provided in plaintext.",
						disk.Encryption.RawKey,
					)
				} else {
					results.AddPassed(&disk)
				}
			}
		}
		for _, disk := range s.Google.Compute.Disks {
			if disk.Encryption.RawKey.Len() > 0 {
				results.Add(
					"Disk encryption key is supplied in plaintext.",
					disk.Encryption.RawKey,
				)
			} else {
				results.AddPassed(&disk)
			}
		}
		return
	},
)
