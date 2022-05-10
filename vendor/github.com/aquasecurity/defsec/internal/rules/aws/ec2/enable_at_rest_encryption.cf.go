package ec2

var cloudFormationEnableAtRestEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      UserData: export SSM_PATH=/database/creds
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            Encrypted: True
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"

`,
}

var cloudFormationEnableAtRestEncryptionBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      UserData: export DATABASE_PASSWORD=password1234
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            Encrypted: False
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"

`,
}

var cloudFormationEnableAtRestEncryptionLinks = []string{}

var cloudFormationEnableAtRestEncryptionRemediationMarkdown = ``
