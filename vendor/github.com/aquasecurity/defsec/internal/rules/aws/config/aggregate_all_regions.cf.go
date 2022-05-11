package config

var cloudFormationAggregateAllRegionsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: true
      ConfigurationAggregatorName: "GoodAccountLevelAggregation"
`, `---
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      OrganizationAggregationSource: 
        AllAwsRegions: true
      ConfigurationAggregatorName: "GoodAccountLevelAggregation"
`,
}

var cloudFormationAggregateAllRegionsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      ConfigurationAggregatorName: "BadAccountLevelAggregation"
`,
}

var cloudFormationAggregateAllRegionsLinks = []string{}

var cloudFormationAggregateAllRegionsRemediationMarkdown = ``
