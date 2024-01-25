package rds

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/test/testutil"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected rds.RDS
	}{
		{
			name: "cluster with instances",
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
`,
			expected: rds.RDS{
				ParameterGroups: []rds.ParameterGroups{
					{
						Metadata:             types.NewTestMisconfigMetadata(),
						DBParameterGroupName: types.String("testgroup", types.NewTestMisconfigMetadata()),
					},
				},
				Clusters: []rds.Cluster{
					{
						Metadata:                  types.NewTestMisconfigMetadata(),
						BackupRetentionPeriodDays: types.Int(2, types.NewTestMisconfigMetadata()),
						Engine:                    types.String("aurora-postgresql", types.NewTestMisconfigMetadata()),
						Encryption: rds.Encryption{
							EncryptStorage: types.Bool(true, types.NewTestMisconfigMetadata()),
							KMSKeyID:       types.String("your-kms-key-id", types.NewTestMisconfigMetadata()),
						},
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: types.NewTestMisconfigMetadata(),
							Enabled:  types.Bool(true, types.NewTestMisconfigMetadata()),
							KMSKeyID: types.String("test-kms-key-id", types.NewTestMisconfigMetadata()),
						},
						PublicAccess:       types.Bool(false, types.NewTestMisconfigMetadata()),
						DeletionProtection: types.Bool(true, types.NewTestMisconfigMetadata()),
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									Metadata:         types.NewTestMisconfigMetadata(),
									StorageEncrypted: types.Bool(true, types.NewTestMisconfigMetadata()),
									Encryption: rds.Encryption{
										EncryptStorage: types.Bool(true, types.NewTestMisconfigMetadata()),
										KMSKeyID:       types.String("your-kms-key-id", types.NewTestMisconfigMetadata()),
									},
									DBInstanceIdentifier:      types.String("test", types.NewTestMisconfigMetadata()),
									PubliclyAccessible:        types.Bool(false, types.NewTestMisconfigMetadata()),
									PublicAccess:              types.BoolDefault(false, types.NewTestMisconfigMetadata()),
									BackupRetentionPeriodDays: types.IntDefault(1, types.NewTestMisconfigMetadata()),
									Engine:                    types.StringDefault("aurora-mysql", types.NewTestMisconfigMetadata()),
									EngineVersion:             types.String("5.7.12", types.NewTestMisconfigMetadata()),
									MultiAZ:                   types.Bool(true, types.NewTestMisconfigMetadata()),
									AutoMinorVersionUpgrade:   types.Bool(true, types.NewTestMisconfigMetadata()),
									DBInstanceArn:             types.String("arn:aws:rds:us-east-2:123456789012:db:my-mysql-instance-1", types.NewTestMisconfigMetadata()),
									IAMAuthEnabled:            types.Bool(true, types.NewTestMisconfigMetadata()),
									PerformanceInsights: rds.PerformanceInsights{
										Metadata: types.NewTestMisconfigMetadata(),
										Enabled:  types.Bool(true, types.NewTestMisconfigMetadata()),
										KMSKeyID: types.String("test-kms-key-id2", types.NewTestMisconfigMetadata()),
									},
									EnabledCloudwatchLogsExports: []types.StringValue{
										types.String("error", types.NewTestMisconfigMetadata()),
										types.String("general", types.NewTestMisconfigMetadata()),
									},
									DBParameterGroups: []rds.DBParameterGroupsList{
										{
											DBParameterGroupName: types.String("testgroup", types.NewTestMisconfigMetadata()),
										},
									},
									TagList: []rds.TagList{
										{
											Metadata: types.NewTestMisconfigMetadata(),
										},
										{
											Metadata: types.NewTestMisconfigMetadata(),
										},
									},
								},
								ClusterIdentifier: types.String("RDSCluster", types.NewTestMisconfigMetadata()),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := testutil.CreateFS(t, map[string]string{
				"template.yaml": tt.source,
			})

			p := parser.New()
			fctx, err := p.ParseFile(context.TODO(), fs, "template.yaml")
			require.NoError(t, err)

			testutil.AssertDefsecEqual(t, tt.expected, Adapt(*fctx))
		})
	}

}
