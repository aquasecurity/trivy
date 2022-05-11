package athena

var cloudFormationEnableAtRestEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
`,
}

var cloudFormationEnableAtRestEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      Name: badExample
      WorkGroupConfiguration:
        ResultConfiguration:
    Type: AWS::Athena::WorkGroup
`,
}

var cloudFormationEnableAtRestEncryptionLinks = []string{}

var cloudFormationEnableAtRestEncryptionRemediationMarkdown = ``
