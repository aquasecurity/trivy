package sqs

var cloudFormationQueueEncryptionUsesCMKGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue

`,
}

var cloudFormationQueueEncryptionUsesCMKBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: alias/aws/sqs
      QueueName: my-queue

`,
}

var cloudFormationQueueEncryptionUsesCMKLinks = []string{}

var cloudFormationQueueEncryptionUsesCMKRemediationMarkdown = ``
