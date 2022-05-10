package s3

var cloudFormationEnableBucketLoggingGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableBucketLoggingBadExamples = []string{
	`---
Resources:
  DisabledEncryptionBucket:
    Properties:
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableBucketLoggingLinks = []string{}

var cloudFormationEnableBucketLoggingRemediationMarkdown = ``
