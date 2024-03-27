package rds

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected rds.RDS
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  RDSCluster:
    Type: 'AWS::RDS::DBCluster'
    Properties:
      DBClusterIdentifier: my-cluster1
      Engine: aurora-postgresql
      StorageEncrypted: true
      KmsKeyId: "your-kms-key-id"
      PerformanceInsightsEnabled: true
      PerformanceInsightsKmsKeyId: "test-kms-key-id"
      PublicAccess: true
      DeletionProtection: true
      BackupRetentionPeriod: 2
  RDSDBInstance1:
    Type: 'AWS::RDS::DBInstance'
    Properties:
      Engine: aurora-mysql
      EngineVersion: "5.7.12"
      DBInstanceIdentifier: test
      DBClusterIdentifier:
        Ref: RDSCluster
      PubliclyAccessible: 'false'
      DBInstanceClass: db.r3.xlarge
      StorageEncrypted: true
      KmsKeyId: "your-kms-key-id"
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "test-kms-key-id2"
      MultiAZ: true
      AutoMinorVersionUpgrade: true
      DBInstanceArn: "arn:aws:rds:us-east-2:123456789012:db:my-mysql-instance-1"
      EnableIAMDatabaseAuthentication: true
      EnableCloudwatchLogsExports: 
        - "error"
        - "general"
      DBParameterGroupName: "testgroup"
      Tags: 
        - Key: "keyname1"
          Value: "value1"
        - Key: "keyname2"
          Value: "value2"
  RDSDBParameterGroup:
    Type: 'AWS::RDS::DBParameterGroup'
    Properties:
      Description: "CloudFormation Sample MySQL Parameter Group"
      DBParameterGroupName: "testgroup"
      Parameters:
        sql_mode: IGNORE_SPACE
  DbSecurityByEC2SecurityGroup: 
    Type: AWS::RDS::DBSecurityGroup
    Properties: 
      GroupDescription: "Ingress for Amazon EC2 security group"
`,
			expected: rds.RDS{
				Classic: rds.Classic{
					DBSecurityGroups: []rds.DBSecurityGroup{{}},
				},
				ParameterGroups: []rds.ParameterGroups{
					{
						DBParameterGroupName: types.StringTest("testgroup"),
					},
				},
				Clusters: []rds.Cluster{
					{
						BackupRetentionPeriodDays: types.IntTest(2),
						Engine:                    types.StringTest("aurora-postgresql"),
						Encryption: rds.Encryption{
							EncryptStorage: types.BoolTest(true),
							KMSKeyID:       types.StringTest("your-kms-key-id"),
						},
						PerformanceInsights: rds.PerformanceInsights{
							Enabled:  types.BoolTest(true),
							KMSKeyID: types.StringTest("test-kms-key-id"),
						},
						PublicAccess:       types.BoolTest(false),
						DeletionProtection: types.BoolTest(true),
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									StorageEncrypted: types.BoolTest(true),
									Encryption: rds.Encryption{
										EncryptStorage: types.BoolTest(true),
										KMSKeyID:       types.StringTest("your-kms-key-id"),
									},
									DBInstanceIdentifier:      types.StringTest("test"),
									PubliclyAccessible:        types.BoolTest(false),
									PublicAccess:              types.BoolTest(false),
									BackupRetentionPeriodDays: types.IntTest(1),
									Engine:                    types.StringTest("aurora-mysql"),
									EngineVersion:             types.StringTest("5.7.12"),
									MultiAZ:                   types.BoolTest(true),
									AutoMinorVersionUpgrade:   types.BoolTest(true),
									DBInstanceArn:             types.StringTest("arn:aws:rds:us-east-2:123456789012:db:my-mysql-instance-1"),
									IAMAuthEnabled:            types.BoolTest(true),
									PerformanceInsights: rds.PerformanceInsights{
										Enabled:  types.BoolTest(true),
										KMSKeyID: types.StringTest("test-kms-key-id2"),
									},
									EnabledCloudwatchLogsExports: []types.StringValue{
										types.StringTest("error"),
										types.StringTest("general"),
									},
									DBParameterGroups: []rds.DBParameterGroupsList{
										{
											DBParameterGroupName: types.StringTest("testgroup"),
										},
									},
									TagList: []rds.TagList{
										{},
										{},
									},
								},
								ClusterIdentifier: types.StringTest("RDSCluster"),
							},
						},
					},
				},
			},
		},
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  RDSCluster:
    Type: 'AWS::RDS::DBCluster'
  RDSDBInstance1:
    Type: 'AWS::RDS::DBInstance'
  RDSDBParameterGroup:
    Type: 'AWS::RDS::DBParameterGroup'
  DbSecurityByEC2SecurityGroup: 
    Type: AWS::RDS::DBSecurityGroup
`,
			expected: rds.RDS{
				Classic: rds.Classic{
					DBSecurityGroups: []rds.DBSecurityGroup{{}},
				},
				ParameterGroups: []rds.ParameterGroups{{}},
				Clusters: []rds.Cluster{{
					Engine:                    types.StringTest("aurora"),
					BackupRetentionPeriodDays: types.IntTest(1),
				}},
				Instances: []rds.Instance{{
					BackupRetentionPeriodDays: types.IntTest(1),
					PublicAccess:              types.BoolTest(true),
					DBParameterGroups:         []rds.DBParameterGroupsList{{}},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
