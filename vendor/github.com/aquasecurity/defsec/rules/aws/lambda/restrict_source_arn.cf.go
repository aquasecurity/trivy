package lambda

var cloudFormationRestrictSourceArnGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036
  GoodPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref BadExample
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com
      SourceArn: "lambda.amazonaws.com"
  
`,
}

var cloudFormationRestrictSourceArnBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036
  BadPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref BadExample
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com

`,
}

var cloudFormationRestrictSourceArnLinks = []string{}

var cloudFormationRestrictSourceArnRemediationMarkdown = ``
