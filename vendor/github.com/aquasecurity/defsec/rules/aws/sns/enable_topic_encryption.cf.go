package sns

var cloudFormationEnableTopicEncryptionGoodExamples = []string{
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

var cloudFormationEnableTopicEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of topic
Resources:
  Queue:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: blah

`,
}

var cloudFormationEnableTopicEncryptionLinks = []string{}

var cloudFormationEnableTopicEncryptionRemediationMarkdown = ``
