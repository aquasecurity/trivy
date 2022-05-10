package rds

var cloudFormationNoPublicDbAccessGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false

`,
}

var cloudFormationNoPublicDbAccessBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true

`,
}

var cloudFormationNoPublicDbAccessLinks = []string{}

var cloudFormationNoPublicDbAccessRemediationMarkdown = ``
