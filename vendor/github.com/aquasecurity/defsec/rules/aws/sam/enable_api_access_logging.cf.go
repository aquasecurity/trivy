package sam

var cloudFormationEnableApiAccessLoggingGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
    Properties:
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: false
      Domain:
        SecurityPolicy: TLS_1_2
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json
`,
}

var cloudFormationEnableApiAccessLoggingBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
    Properties:
      Name: Bad SAM API example
      StageName: Prod
      TracingEnabled: false
`,
}

var cloudFormationEnableApiAccessLoggingLinks = []string{}

var cloudFormationEnableApiAccessLoggingRemediationMarkdown = ``
