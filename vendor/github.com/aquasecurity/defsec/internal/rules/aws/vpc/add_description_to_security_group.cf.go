package vpc

var cloudFormationAddDescriptionToSecurityGroupGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of group description
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "-1"
`,
}

var cloudFormationAddDescriptionToSecurityGroupBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of group description
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "-1"
`,
}

var cloudFormationAddDescriptionToSecurityGroupLinks = []string{}

var cloudFormationAddDescriptionToSecurityGroupRemediationMarkdown = ``
