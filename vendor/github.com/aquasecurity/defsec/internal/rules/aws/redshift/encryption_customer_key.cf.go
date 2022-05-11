package redshift

var cloudFormationEncryptionCustomerKeyGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true
      KmsKeyId: "something"

`,
}

var cloudFormationEncryptionCustomerKeyBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true
`,
}

var cloudFormationEncryptionCustomerKeyLinks = []string{}

var cloudFormationEncryptionCustomerKeyRemediationMarkdown = ``
