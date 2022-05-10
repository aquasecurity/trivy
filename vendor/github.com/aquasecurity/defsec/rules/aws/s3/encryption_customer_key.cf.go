package s3

var cloudFormationCheckEncryptionCustomerKeyGoodExamples = []string{
	`
Resources:
  GoodExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
            ServerSideEncryptionByDefault:
              KMSMasterKeyID: kms-arn
              SSEAlgorithm: aws:kms
    Type: AWS::S3::Bucket
`,
}

var cloudFormationCheckEncryptionCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: false
            ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
    Type: AWS::S3::Bucket
`,
}

var cloudFormationCheckEncryptionCustomerKeyLinks = []string{}

var cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown = ``
