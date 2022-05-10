package msk

var cloudFormationEnableInTransitEncryptionGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS"
`,
}

var cloudFormationEnableInTransitEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS_PLAINTEXT"

`,
}

var cloudFormationEnableInTransitEncryptionLinks = []string{}

var cloudFormationEnableInTransitEncryptionRemediationMarkdown = ``
