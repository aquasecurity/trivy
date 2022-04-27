package autoscaling

var cloudFormationNoSecretsInUserDataGoodExamples = []string{
	`---
Resources:
  InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      InstanceProfileName: MyIamInstanceProfile
      Path: "/"
      Roles:
      - MyAdminRole
  GoodExample:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: MyLaunchTemplate
      LaunchTemplateData:
        IamInstanceProfile:
          Arn: !GetAtt
            - MyIamInstanceProfile
            - Arn
        DisableApiTermination: true
        ImageId: ami-04d5cc9b88example
        UserData: export SSM_PATH=/database/creds
        InstanceType: t2.micro
        KeyName: MyKeyPair
        MetadataOptions:
          - HttpTokens: required
        SecurityGroupIds:
          - sg-083cd3bfb8example
`,
}

var cloudFormationNoSecretsInUserDataBadExamples = []string{
	`---
Resources:
  InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      InstanceProfileName: MyIamInstanceProfile
      Path: "/"
      Roles:
      - MyAdminRole
  BadExample:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: MyLaunchTemplate
      LaunchTemplateData:
        IamInstanceProfile:
          Arn: !GetAtt
            - MyIamInstanceProfile
            - Arn
        DisableApiTermination: true
        ImageId: ami-04d5cc9b88example
        UserData: export DATABASE_PASSWORD=password1234
        InstanceType: t2.micro
        KeyName: MyKeyPair
        SecurityGroupIds:
          - sg-083cd3bfb8example
`,
}

var cloudFormationNoSecretsInUserDataLinks = []string{}

var cloudFormationNoSecretsInUserDataRemediationMarkdown = ``
