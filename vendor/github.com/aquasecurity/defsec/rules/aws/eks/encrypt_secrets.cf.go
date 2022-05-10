package eks

var cloudFormationEncryptSecretsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: 'AWS::EKS::Cluster'
    Properties:
      Name: goodExample
      Version: '1.14'
      RoleArn: >-
        arn:aws:iam::012345678910:role/eks-service-role-good-example
      EncryptionConfig:
        Provider:
          KeyArn: alias/eks-kms
        Resources:
        - secrets
      ResourcesVpcConfig:
        SecurityGroupIds:
          - sg-6979fe18
        SubnetIds:
          - subnet-6782e71e
          - subnet-e7e761ac
`,
}

var cloudFormationEncryptSecretsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: 'AWS::EKS::Cluster'
    Properties:
      Name: badExample
      Version: '1.14'
      RoleArn: >-
        arn:aws:iam::012345678910:role/eks-service-role-bad-example
      ResourcesVpcConfig:
        SecurityGroupIds:
          - sg-6979fe18
        SubnetIds:
          - subnet-6782e71e
          - subnet-e7e761ac
`,
}

var cloudFormationEncryptSecretsLinks = []string{}

var cloudFormationEncryptSecretsRemediationMarkdown = ``
