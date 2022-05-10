package cloudtrail

var cloudFormationEnableAllRegionsGoodExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
`,
}

var cloudFormationEnableAllRegionsBadExamples = []string{
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

var cloudFormationEnableAllRegionsLinks = []string{}

var cloudFormationEnableAllRegionsRemediationMarkdown = ``
