package s3

var cloudFormationSpecifyPublicAccessBlockGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
    Type: AWS::S3::Bucket
`,
}

var cloudFormationSpecifyPublicAccessBlockBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket
`,
}

var cloudFormationSpecifyPublicAccessBlockLinks = []string{}

var cloudFormationSpecifyPublicAccessBlockRemediationMarkdown = ``
