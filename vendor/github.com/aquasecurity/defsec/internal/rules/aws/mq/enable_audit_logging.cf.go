package mq

var cloudFormationEnableAuditLoggingGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        Audit: true

`,
}

var cloudFormationEnableAuditLoggingBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        Audit: false

`,
}

var cloudFormationEnableAuditLoggingLinks = []string{}

var cloudFormationEnableAuditLoggingRemediationMarkdown = ``
