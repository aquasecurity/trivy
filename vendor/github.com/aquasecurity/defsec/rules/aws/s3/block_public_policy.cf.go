package s3

var cloudFormationBlockPublicPolicyGoodExamples = []string{
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

var cloudFormationBlockPublicPolicyBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket
`,
}

var cloudFormationBlockPublicPolicyLinks = []string{}

var cloudFormationBlockPublicPolicyRemediationMarkdown = ``
