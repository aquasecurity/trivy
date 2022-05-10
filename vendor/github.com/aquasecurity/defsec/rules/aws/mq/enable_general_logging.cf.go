package mq

var cloudFormationEnableGeneralLoggingGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        General: true

`,
}

var cloudFormationEnableGeneralLoggingBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        General: false

`,
}

var cloudFormationEnableGeneralLoggingLinks = []string{}

var cloudFormationEnableGeneralLoggingRemediationMarkdown = ``
