package sqs

var cloudFormationNoWildcardsInPolicyDocumentsGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of queue policy
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      Name: something
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - Ref: MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "SQS:SendMessage" 
              - "SQS:ReceiveMessage"
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:  
              AWS: 
                - "111122223333"        
`,
}

var cloudFormationNoWildcardsInPolicyDocumentsBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of queue policy
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      Name: something
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - !Ref MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "*" 
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:  
              AWS: 
                - "111122223333"        
`,
}

var cloudFormationNoWildcardsInPolicyDocumentsLinks = []string{}

var cloudFormationNoWildcardsInPolicyDocumentsRemediationMarkdown = ``
