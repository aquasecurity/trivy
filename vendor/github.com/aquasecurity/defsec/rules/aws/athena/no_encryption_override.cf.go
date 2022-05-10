package athena

var cloudFormationNoEncryptionOverrideGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: true
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
`,
}

var cloudFormationNoEncryptionOverrideBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      Name: badExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: false
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
`,
}

var cloudFormationNoEncryptionOverrideLinks = []string{}

var cloudFormationNoEncryptionOverrideRemediationMarkdown = ``
