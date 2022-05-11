package sns

var cloudFormationTopicEncryptionUsesCMKGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of topic
Resources:
  Queue:
    Type: AWS::SQS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key

`,
}

var cloudFormationTopicEncryptionUsesCMKBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of topic
Resources:
  Queue:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: alias/aws/sns

`,
}

var cloudFormationTopicEncryptionUsesCMKLinks = []string{}

var cloudFormationTopicEncryptionUsesCMKRemediationMarkdown = ``
