package ecr

var cloudFormationEnableImageScansGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagImmutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: True
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
`,
}

var cloudFormationEnableImageScansBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: False
`,
}

var cloudFormationEnableImageScansLinks = []string{}

var cloudFormationEnableImageScansRemediationMarkdown = ``
