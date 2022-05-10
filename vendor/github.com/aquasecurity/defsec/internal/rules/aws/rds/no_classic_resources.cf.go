package rds

var cloudFormationNoClassicResourcesGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:

`,
}

var cloudFormationNoClassicResourcesBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of rds sgr
Resources:
  Queue:
    Type: AWS::RDS::DBSecurityGroup
    Properties:
      Description: ""

`,
}

var cloudFormationNoClassicResourcesLinks = []string{}

var cloudFormationNoClassicResourcesRemediationMarkdown = ``
