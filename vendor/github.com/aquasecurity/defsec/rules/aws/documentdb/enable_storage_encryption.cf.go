package documentdb

var cloudFormationEnableStorageEncryptionGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: "AWS::DocDB::DBCluster"
    Properties:
      BackupRetentionPeriod : 8
      DBClusterIdentifier : "sample-cluster"
      DBClusterParameterGroupName : "default.docdb3.6"
      KmsKeyId : "your-kms-key-id"
      StorageEncrypted: true
      EnableCloudwatchLogsExports:
      - audit
      - profiler
  InstanceInstanceExample:
    Type: "AWS::DocDB::DBInstance"
    Properties:
      AutoMinorVersionUpgrade: true
      AvailabilityZone: "us-east-1c"
      DBClusterIdentifier: "sample-cluster"
      DBInstanceClass: "db.r5.large"
      DBInstanceIdentifier: "sample-cluster-instance-0"
      PreferredMaintenanceWindow: "sat:06:54-sat:07:24"
`,
}

var cloudFormationEnableStorageEncryptionBadExamples = []string{
	`---
 Resources:
  BadExample:
    Type: "AWS::DocDB::DBCluster"
    Properties:
      BackupRetentionPeriod: 8
      DBClusterIdentifier: sample-cluster
      DBClusterParameterGroupName: default.docdb3.6
  BadInstanceExample:
    Type: "AWS::DocDB::DBInstance"
    Properties:
      AutoMinorVersionUpgrade: true
      AvailabilityZone: us-east-1c
      DBClusterIdentifier: sample-cluster
      DBInstanceClass: db.r5.large
      DBInstanceIdentifier: sample-cluster-instance-0
      PreferredMaintenanceWindow: 'sat:06:54-sat:07:24'
`,
}

var cloudFormationEnableStorageEncryptionLinks = []string{}

var cloudFormationEnableStorageEncryptionRemediationMarkdown = ``
