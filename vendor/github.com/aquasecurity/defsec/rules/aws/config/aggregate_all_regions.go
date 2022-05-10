package config

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAggregateAllRegions = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0019",
		Provider:   providers.AWSProvider,
		Service:    "config",
		ShortCode:  "aggregate-all-regions",
		Summary:    "Config configuration aggregator should be using all regions for source",
		Impact:     "Sources that aren't covered by the aggregator are not include in the configuration",
		Resolution: "Set the aggregator to cover all regions",
		Explanation: `The configuration aggregator should be configured with all_regions for the source. 

This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.`,
		Links: []string{
			"https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformAggregateAllRegionsGoodExamples,
			BadExamples:         terraformAggregateAllRegionsBadExamples,
			Links:               terraformAggregateAllRegionsLinks,
			RemediationMarkdown: terraformAggregateAllRegionsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationAggregateAllRegionsGoodExamples,
			BadExamples:         cloudFormationAggregateAllRegionsBadExamples,
			Links:               cloudFormationAggregateAllRegionsLinks,
			RemediationMarkdown: cloudFormationAggregateAllRegionsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		if !s.AWS.Config.ConfigurationAggregrator.IsDefined {
			return
		}
		if s.AWS.Config.ConfigurationAggregrator.SourceAllRegions.IsFalse() {
			results.Add(
				"Configuration aggregation is not set to source from all regions.",
				s.AWS.Config.ConfigurationAggregrator.SourceAllRegions,
			)
		} else {
			results.AddPassed(s.AWS.Config.ConfigurationAggregrator.SourceAllRegions)
		}
		return
	},
)
