package sqs

var cloudFormationEnableQueueEncryptionGoodExamples = []string{
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

var cloudFormationEnableQueueEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue

`,
}

var cloudFormationEnableQueueEncryptionLinks = []string{}

var cloudFormationEnableQueueEncryptionRemediationMarkdown = ``
