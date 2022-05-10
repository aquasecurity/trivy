package msk

var cloudFormationEnableLoggingGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          S3:
            Enabled: true


`,
}

var cloudFormationEnableLoggingBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          CloudWatchLogs:
            Enabled: false

`,
}

var cloudFormationEnableLoggingLinks = []string{}

var cloudFormationEnableLoggingRemediationMarkdown = ``
