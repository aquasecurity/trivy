package compute

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoProjectWideSshKeys = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0030",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-project-wide-ssh-keys",
		Summary:     "Disable project-wide SSH keys for all instances",
		Impact:      "Compromise of a single key pair compromises all instances",
		Resolution:  "Disable project-wide SSH keys",
		Explanation: `Use of project-wide SSH keys means that a compromise of any one of these key pairs can result in all instances being compromised. It is recommended to use instance-level keys.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoProjectWideSshKeysGoodExamples,
			BadExamples:         terraformNoProjectWideSshKeysBadExamples,
			Links:               terraformNoProjectWideSshKeysLinks,
			RemediationMarkdown: terraformNoProjectWideSshKeysRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.EnableProjectSSHKeyBlocking.IsFalse() {
				results.Add(
					"Instance allows use of project-level SSH keys.",
					instance.EnableProjectSSHKeyBlocking,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
