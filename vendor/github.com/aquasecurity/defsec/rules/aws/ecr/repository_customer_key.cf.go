package ecr

var cloudFormationRepositoryCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagImmutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: false
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
`,
}

var cloudFormationRepositoryCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: false
`,
}

var cloudFormationRepositoryCustomerKeyLinks = []string{}

var cloudFormationRepositoryCustomerKeyRemediationMarkdown = ``
