package s3

var cloudFormationIgnorePublicAclsGoodExamples = []string{
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

var cloudFormationIgnorePublicAclsBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket
`,
}

var cloudFormationIgnorePublicAclsLinks = []string{}

var cloudFormationIgnorePublicAclsRemediationMarkdown = ``
