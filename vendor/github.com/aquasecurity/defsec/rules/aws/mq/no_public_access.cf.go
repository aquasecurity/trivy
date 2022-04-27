package mq

var cloudFormationNoPublicAccessGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: false

`,
}

var cloudFormationNoPublicAccessBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: true

`,
}

var cloudFormationNoPublicAccessLinks = []string{}

var cloudFormationNoPublicAccessRemediationMarkdown = ``
