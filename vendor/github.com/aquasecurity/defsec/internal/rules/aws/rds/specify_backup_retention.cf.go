package rds

var cloudFormationSpecifyBackupRetentionGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      BackupRetentionPeriod: 30

`,
}

var cloudFormationSpecifyBackupRetentionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:

`,
}

var cloudFormationSpecifyBackupRetentionLinks = []string{}

var cloudFormationSpecifyBackupRetentionRemediationMarkdown = ``
