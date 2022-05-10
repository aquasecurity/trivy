package apigateway

var cloudFormationEnableAccessLoggingGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of ApiGateway
Resources:
  GoodApi:
    Type: AWS::ApiGatewayV2::Api
  GoodApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json
      ApiId: !Ref GoodApi
      StageName: GoodApiStage
`,
}

var cloudFormationEnableAccessLoggingBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of ApiGateway
Resources:
  BadApi:
    Type: AWS::ApiGatewayV2::Api
  BadApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        Format: json
      ApiId: !Ref BadApi
      StageName: BadApiStage
`,
}

var cloudFormationEnableAccessLoggingLinks = []string{}

var cloudFormationEnableAccessLoggingRemediationMarkdown = ``
