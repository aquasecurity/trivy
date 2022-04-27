package sam

var cloudFormationEnableHttpApiAccessLoggingGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Activey
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json
`,
}

var cloudFormationEnableHttpApiAccessLoggingBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  HttpApi:
    Type: AWS::Serverless::HttpApi
    Properties:
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Passthrough
`,
}

var cloudFormationEnableHttpApiAccessLoggingLinks = []string{}

var cloudFormationEnableHttpApiAccessLoggingRemediationMarkdown = ``
