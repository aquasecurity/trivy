package sam

var cloudFormationEnableTableEncryptionGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Table
Resources:
  GoodFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: GoodTable
      SSESpecification:
        SSEEnabled: true
`,
}

var cloudFormationEnableTableEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM Table
Resources:
  BadFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: Bad Table
      SSESpecification:
        SSEEnabled: false
`, `---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM Table
Resources:
  BadFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: Bad Table
`,
}

var cloudFormationEnableTableEncryptionLinks = []string{}

var cloudFormationEnableTableEncryptionRemediationMarkdown = ``
