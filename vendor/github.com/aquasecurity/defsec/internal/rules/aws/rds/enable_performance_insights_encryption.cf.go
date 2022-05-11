package rds

var cloudFormationEnablePerformanceInsightsEncryptionGoodExamples = []string{
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

var cloudFormationEnablePerformanceInsightsEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true

`,
}

var cloudFormationEnablePerformanceInsightsEncryptionLinks = []string{}

var cloudFormationEnablePerformanceInsightsEncryptionRemediationMarkdown = ``
