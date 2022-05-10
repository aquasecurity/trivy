package rds

var cloudFormationEnablePerformanceInsightsGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"

`,
}

var cloudFormationEnablePerformanceInsightsBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: false

`,
}

var cloudFormationEnablePerformanceInsightsLinks = []string{}

var cloudFormationEnablePerformanceInsightsRemediationMarkdown = ``
