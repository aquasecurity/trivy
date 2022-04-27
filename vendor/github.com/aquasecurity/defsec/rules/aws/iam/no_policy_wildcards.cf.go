package iam

var cloudFormationNoPolicyWildcardsGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of policy
Resources:
  GoodPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: CFNUsers
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - 's3:ListBuckets'
            Resource: 'specific-bucket'
`,
}

var cloudFormationNoPolicyWildcardsBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of policy
Resources:
  BadPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: CFNUsers
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - 'cloudformation:Describe*'
              - 'cloudformation:List*'
              - 'cloudformation:Get*'
            Resource: '*'
`,
}

var cloudFormationNoPolicyWildcardsLinks = []string{}

var cloudFormationNoPolicyWildcardsRemediationMarkdown = ``
