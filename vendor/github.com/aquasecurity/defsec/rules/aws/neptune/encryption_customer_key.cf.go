package neptune

var cloudFormationCheckEncryptionCustomerKeyGoodExamples = []string{
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

var cloudFormationCheckEncryptionCustomerKeyBadExamples = []string{
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

var cloudFormationCheckEncryptionCustomerKeyLinks = []string{}

var cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown = ``
