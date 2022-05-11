package sam

var cloudFormationNoFunctionPolicyWildcardsGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Function
Resources:
  GoodFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
      Policies:  
        - AWSLambdaExecute
        - Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - s3:GetObject
            - s3:GetObjectACL
            Resource: 'arn:aws:s3:::my-bucket/*'
`,
}

var cloudFormationNoFunctionPolicyWildcardsBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM Function
Resources:
  BadFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
      Policies:  
        - AWSLambdaExecute
        - Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - s3:*
            Resource: 'arn:aws:s3:::my-bucket/*'
`,
}

var cloudFormationNoFunctionPolicyWildcardsLinks = []string{}

var cloudFormationNoFunctionPolicyWildcardsRemediationMarkdown = ``
