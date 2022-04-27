package elasticache

var cloudFormationAddDescriptionForSecurityGroupGoodExamples = []string{
	`---
Resources:
  GoodExampleCacheGroup:
    Type: AWS::ElastiCache::SecurityGroup
    Properties:
      Description: Some description
  GoodExampleEc2SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: GoodExample
      GroupDescription: Good Elasticache Security Group
  GoodSecurityGroupIngress:
    Type: AWS::ElastiCache::SecurityGroupIngress
    Properties: 
      CacheSecurityGroupName: GoodExampleCacheGroup
      EC2SecurityGroupName: GoodExampleEc2SecurityGroup
`,
}

var cloudFormationAddDescriptionForSecurityGroupBadExamples = []string{
	`---
Resources:
  BadExampleCacheGroup:
    Type: AWS::ElastiCache::SecurityGroup
    Properties:
      Tags:
      - Name: BadExample
  BadExampleEc2SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: BadExample
      GroupDescription: Bad Elasticache Security Group
  BadSecurityGroupIngress:
    Type: AWS::ElastiCache::SecurityGroupIngress
    Properties: 
      CacheSecurityGroupName: BadExampleCacheGroup
      EC2SecurityGroupName: BadExampleEc2SecurityGroup
`,
}

var cloudFormationAddDescriptionForSecurityGroupLinks = []string{}

var cloudFormationAddDescriptionForSecurityGroupRemediationMarkdown = ``
