package redshift

var cloudFormationAddDescriptionToSecurityGroupGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift sgr
Resources:
  Queue:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: "Disallow bad stuff"

`,
}

var cloudFormationAddDescriptionToSecurityGroupBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift sgr
Resources:
  Queue:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: ""

`,
}

var cloudFormationAddDescriptionToSecurityGroupLinks = []string{}

var cloudFormationAddDescriptionToSecurityGroupRemediationMarkdown = ``
