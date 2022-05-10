package rds

var cloudFormationEncryptClusterStorageDataGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"

`,
}

var cloudFormationEncryptClusterStorageDataBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of rds sgr
Resources:
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: false

`,
}

var cloudFormationEncryptClusterStorageDataLinks = []string{}

var cloudFormationEncryptClusterStorageDataRemediationMarkdown = ``
