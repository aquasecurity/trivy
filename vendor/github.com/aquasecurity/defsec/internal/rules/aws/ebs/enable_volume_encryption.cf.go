package ebs

var cloudFormationEnableVolumeEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot
`,
}

var cloudFormationEnableVolumeEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      AvailabilityZone: !GetAtt Ec2Instance.AvailabilityZone
    DeletionPolicy: Snapshot
`,
}

var cloudFormationEnableVolumeEncryptionLinks = []string{}

var cloudFormationEnableVolumeEncryptionRemediationMarkdown = ``
