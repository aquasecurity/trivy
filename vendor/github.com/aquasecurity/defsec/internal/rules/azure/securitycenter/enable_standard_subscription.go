package securitycenter

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/azure/securitycenter"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableStandardSubscription = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0045",
		Provider:   providers.AzureProvider,
		Service:    "security-center",
		ShortCode:  "enable-standard-subscription",
		Summary:    "Enable the standard security center subscription tier",
		Impact:     "Using free subscription does not enable Azure Defender for the resource type",
		Resolution: "Enable standard subscription tier to benefit from Azure Defender",
		Explanation: `To benefit from Azure Defender you should use the Standard subscription tier.
			
			Enabling Azure Defender extends the capabilities of the free mode to workloads running in private and other public clouds, providing unified security management and threat protection across your hybrid cloud workloads.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableStandardSubscriptionGoodExamples,
			BadExamples:         terraformEnableStandardSubscriptionBadExamples,
			Links:               terraformEnableStandardSubscriptionLinks,
			RemediationMarkdown: terraformEnableStandardSubscriptionRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, sub := range s.Azure.SecurityCenter.Subscriptions {
			if sub.IsUnmanaged() {
				continue
			}
			if sub.Tier.EqualTo(securitycenter.TierFree) {
				results.Add(
					"Security center subscription uses the free tier.",
					sub.Tier,
				)
			} else {
				results.AddPassed(&sub)
			}
		}
		return
	},
)
