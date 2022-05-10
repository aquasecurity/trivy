package redshift

var cloudFormationUseVpcGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: "my-subnet-group"

`,
}

var cloudFormationUseVpcBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: ""

`,
}

var cloudFormationUseVpcLinks = []string{}

var cloudFormationUseVpcRemediationMarkdown = ``
