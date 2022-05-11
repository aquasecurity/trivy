package s3

var cloudFormationEnableBucketEncryptionGoodExamples = []string{
	`
Resources:
  GoodExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
            ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableBucketEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: false
            ServerSideEncryptionByDefault:
              KMSMasterKeyID: asdf
              SSEAlgorithm: asdf
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableBucketEncryptionLinks = []string{}

var cloudFormationEnableBucketEncryptionRemediationMarkdown = ``
