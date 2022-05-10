package rds

var cloudFormationEncryptInstanceStorageDataGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:
  Instance:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"

`,
}

var cloudFormationEncryptInstanceStorageDataBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of rds sgr
Resources:
  Instance:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: false

`,
}

var cloudFormationEncryptInstanceStorageDataLinks = []string{}

var cloudFormationEncryptInstanceStorageDataRemediationMarkdown = ``
