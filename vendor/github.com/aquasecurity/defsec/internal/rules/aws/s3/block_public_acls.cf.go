package s3

var cloudFormationBlockPublicAclsGoodExamples = []string{
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

var cloudFormationBlockPublicAclsBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket
`,
}

var cloudFormationBlockPublicAclsLinks = []string{}

var cloudFormationBlockPublicAclsRemediationMarkdown = ``
