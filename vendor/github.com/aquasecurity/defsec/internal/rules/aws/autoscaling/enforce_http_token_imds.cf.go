package autoscaling

var cloudformationEnforceHttpTokenImdsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      MetadataOptions:
        HttpTokens: required
        HttpEndpoint: enabled
 `,
}

var cloudformationEnforceHttpTokenImdsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      MetadataOptions:
        HttpTokens: optional
        HttpEndpoint: enabled
 `,
}

var cloudformationEnforceHttpTokenImdsLinks = []string{}

var cloudformationEnforceHttpTokenImdsRemediationMarkdown = ``
