package rds

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/require"
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
						Metadata:             types.NewTestMetadata(),
						DBParameterGroupName: types.String("testgroup", types.NewTestMetadata()),
					},
				},
				Clusters: []rds.Cluster{
					{
						Metadata:                  types.NewTestMetadata(),
						BackupRetentionPeriodDays: types.Int(2, types.NewTestMetadata()),
						Engine:                    types.String("aurora-postgresql", types.NewTestMetadata()),
						Encryption: rds.Encryption{
							EncryptStorage: types.Bool(true, types.NewTestMetadata()),
							KMSKeyID:       types.String("your-kms-key-id", types.NewTestMetadata()),
						},
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyID: types.String("test-kms-key-id", types.NewTestMetadata()),
						},
						PublicAccess:       types.Bool(false, types.NewTestMetadata()),
						DeletionProtection: types.Bool(true, types.NewTestMetadata()),
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									Metadata:         types.NewTestMetadata(),
									StorageEncrypted: types.Bool(true, types.NewTestMetadata()),
									Encryption: rds.Encryption{
										EncryptStorage: types.Bool(true, types.NewTestMetadata()),
										KMSKeyID:       types.String("your-kms-key-id", types.NewTestMetadata()),
									},
									DBInstanceIdentifier:      types.String("test", types.NewTestMetadata()),
									PubliclyAccessible:        types.Bool(false, types.NewTestMetadata()),
									PublicAccess:              types.BoolDefault(false, types.NewTestMetadata()),
									BackupRetentionPeriodDays: types.IntDefault(1, types.NewTestMetadata()),
									Engine:                    types.StringDefault("aurora-mysql", types.NewTestMetadata()),
									EngineVersion:             types.String("5.7.12", types.NewTestMetadata()),
									MultiAZ:                   types.Bool(true, types.NewTestMetadata()),
									AutoMinorVersionUpgrade:   types.Bool(true, types.NewTestMetadata()),
									DBInstanceArn:             types.String("arn:aws:rds:us-east-2:123456789012:db:my-mysql-instance-1", types.NewTestMetadata()),
									IAMAuthEnabled:            types.Bool(true, types.NewTestMetadata()),
									PerformanceInsights: rds.PerformanceInsights{
										Metadata: types.NewTestMetadata(),
										Enabled:  types.Bool(true, types.NewTestMetadata()),
										KMSKeyID: types.String("test-kms-key-id2", types.NewTestMetadata()),
									},
									EnabledCloudwatchLogsExports: []types.StringValue{
										types.String("error", types.NewTestMetadata()),
										types.String("general", types.NewTestMetadata()),
									},
									DBParameterGroups: []rds.DBParameterGroupsList{
										{
											DBParameterGroupName: types.String("testgroup", types.NewTestMetadata()),
										},
									},
									TagList: []rds.TagList{
										{
											Metadata: types.NewTestMetadata(),
										},
										{
											Metadata: types.NewTestMetadata(),
										},
									},
								},
								ClusterIdentifier: types.String("RDSCluster", types.NewTestMetadata()),
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
