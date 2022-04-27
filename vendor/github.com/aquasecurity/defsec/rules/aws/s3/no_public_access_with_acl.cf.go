package s3

var cloudFormationNoPublicAccessWithAclGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      AccessControl: Private
    Type: AWS::S3::Bucket
`,
}

var cloudFormationNoPublicAccessWithAclBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket
`,
}

var cloudFormationNoPublicAccessWithAclLinks = []string{}

var cloudFormationNoPublicAccessWithAclRemediationMarkdown = ``
