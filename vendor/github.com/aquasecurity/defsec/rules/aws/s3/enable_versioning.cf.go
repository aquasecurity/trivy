package s3

var cloudFormationEnableVersioningGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      VersioningConfiguration:
        Status: Enabled
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableVersioningBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
`,
}

var cloudFormationEnableVersioningLinks = []string{}

var cloudFormationEnableVersioningRemediationMarkdown = ``
