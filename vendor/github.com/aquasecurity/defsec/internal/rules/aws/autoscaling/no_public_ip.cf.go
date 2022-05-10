package autoscaling

var cloudFormationNoPublicIpGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
`,
}

var cloudFormationNoPublicIpBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      AssociatePublicIpAddress: true
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
`,
}

var cloudFormationNoPublicIpLinks = []string{}

var cloudFormationNoPublicIpRemediationMarkdown = ``
