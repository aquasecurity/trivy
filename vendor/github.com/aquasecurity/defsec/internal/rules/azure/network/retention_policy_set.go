package network

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRetentionPolicySet = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0049",
		Provider:   providers.AzureProvider,
		Service:    "network",
		ShortCode:  "retention-policy-set",
		Summary:    "Retention policy for flow logs should be enabled and set to greater than 90 days",
		Impact:     "Not enabling retention or having short expiry on flow logs could lead to compromise being undetected limiting time for analysis",
		Resolution: "Ensure flow log retention is turned on with an expiry of >90 days",
		Explanation: `Flow logs are the source of truth for all network activity in your cloud environment. 
To enable analysis in security event that was detected late, you need to have the logs available. 
			
Setting an retention policy will help ensure as much information is available for review.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRetentionPolicySetGoodExamples,
			BadExamples:         terraformRetentionPolicySetBadExamples,
			Links:               terraformRetentionPolicySetLinks,
			RemediationMarkdown: terraformRetentionPolicySetRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, flowLog := range s.Azure.Network.NetworkWatcherFlowLogs {
			if flowLog.IsUnmanaged() {
				continue
			}
			if flowLog.RetentionPolicy.Enabled.IsFalse() {
				results.Add(
					"Flow log does not enable the log retention policy.",
					flowLog.RetentionPolicy.Enabled,
				)
			} else if flowLog.RetentionPolicy.Days.LessThan(90) {
				results.Add(
					"Flow log has a log retention policy of less than 90 days.",
					flowLog.RetentionPolicy.Days,
				)
			} else {
				results.AddPassed(&flowLog)
			}
		}
		return
	},
)
