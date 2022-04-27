package cloudfront

var cloudFormationUseSecureTlsPolicyGoodExamples = []string{
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
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.2_2021
    Type: AWS::CloudFront::Distribution
`,
}

var cloudFormationUseSecureTlsPolicyBadExamples = []string{
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
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.0
    Type: AWS::CloudFront::Distribution
`,
}

var cloudFormationUseSecureTlsPolicyLinks = []string{}

var cloudFormationUseSecureTlsPolicyRemediationMarkdown = ``
