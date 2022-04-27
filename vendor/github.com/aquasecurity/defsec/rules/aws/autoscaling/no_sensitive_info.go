package autoscaling

import (
	"fmt"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/owenrumney/squealer/pkg/squealer"
)

var CheckNoSensitiveInfo = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0122",
		Provider:    providers.AWSProvider,
		Service:     "autoscaling",
		ShortCode:   "no-sensitive-info",
		Summary:     "Ensure all data stored in the launch configuration EBS is securely encrypted",
		Impact:      "Sensitive credentials in user data can be leaked",
		Resolution:  "Don't use sensitive data in user data",
		Explanation: `When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoSensitiveInfoGoodExamples,
			BadExamples:         terraformNoSensitiveInfoBadExamples,
			Links:               terraformNoSensitiveInfoLinks,
			RemediationMarkdown: terraformNoSensitiveInfoRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		scanner := squealer.NewStringScanner()
		for _, launchConfig := range s.AWS.Autoscaling.LaunchConfigurations {
			if result := scanner.Scan(launchConfig.UserData.Value()); result.TransgressionFound {
				results.Add(
					fmt.Sprintf("Sensitive data found in user data: %s", result.Description),
					launchConfig.UserData,
				)
			} else {
				results.AddPassed(&launchConfig)
			}
		}
		return
	},
)
