package vpc

var cloudFormationNoPublicIngressSgrGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of ingress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupIngress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "6"
`,
}

var cloudFormationNoPublicIngressSgrBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of ingress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupIngress:
      - CidrIp: 80.1.2.3/32
        IpProtocol: "6"
`,
}

var cloudFormationNoPublicIngressSgrLinks = []string{}

var cloudFormationNoPublicIngressSgrRemediationMarkdown = ``
