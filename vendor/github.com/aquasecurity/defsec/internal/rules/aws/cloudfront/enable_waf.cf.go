package cloudfront

var cloudFormationEnableWafGoodExamples = []string{
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
        WebACLId: waf_id
    Type: AWS::CloudFront::Distribution
`,
}

var cloudFormationEnableWafBadExamples = []string{
	`---
Resources:
  BadExample:
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

var cloudFormationEnableWafLinks = []string{}

var cloudFormationEnableWafRemediationMarkdown = ``
