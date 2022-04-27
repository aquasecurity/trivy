package neptune

var cloudFormationEnableStorageEncryptionGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"

`,
}

var cloudFormationEnableStorageEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: false

`,
}

var cloudFormationEnableStorageEncryptionLinks = []string{}

var cloudFormationEnableStorageEncryptionRemediationMarkdown = ``
