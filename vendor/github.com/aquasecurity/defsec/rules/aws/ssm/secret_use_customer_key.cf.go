package ssm

var cloudFormationSecretUseCustomerKeyGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of ingress rule
Resources:
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      KmsKeyId: "my-key-id"
      Name: "blah"
      SecretString: "don't tell anyone"
`,
}

var cloudFormationSecretUseCustomerKeyBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of secret
Resources:
  BadSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      Name: "blah"
      SecretString: "don't tell anyone"
`,
}

var cloudFormationSecretUseCustomerKeyLinks = []string{}

var cloudFormationSecretUseCustomerKeyRemediationMarkdown = ``
