package config

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAggregateAllRegions = rules.Register(
	scan.Rule{
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
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAggregateAllRegionsGoodExamples,
			BadExamples:         terraformAggregateAllRegionsBadExamples,
			Links:               terraformAggregateAllRegionsLinks,
			RemediationMarkdown: terraformAggregateAllRegionsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationAggregateAllRegionsGoodExamples,
			BadExamples:         cloudFormationAggregateAllRegionsBadExamples,
			Links:               cloudFormationAggregateAllRegionsLinks,
			RemediationMarkdown: cloudFormationAggregateAllRegionsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
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
