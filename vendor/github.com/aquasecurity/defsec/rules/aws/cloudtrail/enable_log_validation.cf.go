package cloudtrail

var cloudFormationEnableLogValidationGoodExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
`,
}

var cloudFormationEnableLogValidationBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: false
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
`,
}

var cloudFormationEnableLogValidationLinks = []string{}

var cloudFormationEnableLogValidationRemediationMarkdown = ``
