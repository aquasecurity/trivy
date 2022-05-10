package cloudfront

var cloudFormationEnableLoggingGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
    Type: AWS::CloudFront::Distribution
`,
}

var cloudFormationEnableLoggingBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
    Type: AWS::CloudFront::Distribution
`,
}

var cloudFormationEnableLoggingLinks = []string{}

var cloudFormationEnableLoggingRemediationMarkdown = ``
