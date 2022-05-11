package s3

var cloudFormationNoPublicBucketsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
    Type: AWS::S3::Bucket
`,
}

var cloudFormationNoPublicBucketsBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket
`,
}

var cloudFormationNoPublicBucketsLinks = []string{}

var cloudFormationNoPublicBucketsRemediationMarkdown = ``
