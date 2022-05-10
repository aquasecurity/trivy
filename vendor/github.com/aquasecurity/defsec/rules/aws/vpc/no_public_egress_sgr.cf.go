package vpc

var cloudFormationNoPublicEgressSgrGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of egress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "6"
`,
}

var cloudFormationNoPublicEgressSgrBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of egress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 80.1.2.3/32
        IpProtocol: "6"
`,
}

var cloudFormationNoPublicEgressSgrLinks = []string{}

var cloudFormationNoPublicEgressSgrRemediationMarkdown = ``
