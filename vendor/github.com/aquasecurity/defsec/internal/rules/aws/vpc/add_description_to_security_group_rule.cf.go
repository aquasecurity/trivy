package vpc

var cloudFormationAddDescriptionToSecurityGroupRuleGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of SGR description
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        Description: "Can connect to loopback"
        IpProtocol: "-1"
`,
}

var cloudFormationAddDescriptionToSecurityGroupRuleBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of SGR description
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "-1"
`,
}

var cloudFormationAddDescriptionToSecurityGroupRuleLinks = []string{}

var cloudFormationAddDescriptionToSecurityGroupRuleRemediationMarkdown = ``
