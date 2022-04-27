package cloudwatch

var cloudFormationLogGroupCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Logs::LogGroup
    Properties:
      KmsKeyId: "arn:aws:kms:us-west-2:111122223333:key/lambdalogging"
      LogGroupName: "aws/lambda/goodExample"
      RetentionInDays: 30
`,
}

var cloudFormationLogGroupCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Logs::LogGroup
    Properties:
      KmsKeyId: ""
      LogGroupName: "aws/lambda/badExample"
      RetentionInDays: 30
`,
}

var cloudFormationLogGroupCustomerKeyLinks = []string{}

var cloudFormationLogGroupCustomerKeyRemediationMarkdown = ``
