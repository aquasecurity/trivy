package redshift

var cloudFormationNoClassicResourcesGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift sgr
Resources:

`,
}

var cloudFormationNoClassicResourcesBadExamples = []string{
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

var cloudFormationNoClassicResourcesLinks = []string{}

var cloudFormationNoClassicResourcesRemediationMarkdown = ``
