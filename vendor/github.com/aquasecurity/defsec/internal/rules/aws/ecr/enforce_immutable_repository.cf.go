package ecr

var cloudFormationEnforceImmutableRepositoryGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagMutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: false
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
`,
}

var cloudFormationEnforceImmutableRepositoryBadExamples = []string{
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

var cloudFormationEnforceImmutableRepositoryLinks = []string{}

var cloudFormationEnforceImmutableRepositoryRemediationMarkdown = ``
