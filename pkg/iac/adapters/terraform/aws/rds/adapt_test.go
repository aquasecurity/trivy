package rds

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  rds.RDS
	}{
		{
			name: "defined",
			terraform: `

			resource "aws_rds_cluster" "example" {
				engine                  = "aurora-mysql"
				availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
				backup_retention_period = 7
				kms_key_id  = "kms_key_1"
				storage_encrypted = true
				replication_source_identifier = "arn-of-a-source-db-cluster"
				deletion_protection = true
			  }
	
			resource "aws_rds_cluster_instance" "example" {
				cluster_identifier      = aws_rds_cluster.example.id
				name = "bar"
				performance_insights_enabled = true
				performance_insights_kms_key_id = "performance_key_0"
				kms_key_id  = "kms_key_0"
				storage_encrypted = true
			}

			resource "aws_db_security_group" "example" {
				# ...
			}

			resource "aws_db_instance" "example" {
				publicly_accessible = false
				backup_retention_period = 5
				skip_final_snapshot  = true
				performance_insights_enabled = true
				performance_insights_kms_key_id = "performance_key_1"
				storage_encrypted = true
				kms_key_id = "kms_key_2"
			}
`,
			expected: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  iacTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: iacTypes.Int(5, iacTypes.NewTestMetadata()),
						ReplicationSourceARN:      iacTypes.String("", iacTypes.NewTestMetadata()),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: iacTypes.NewTestMetadata(),
							Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							KMSKeyID: iacTypes.String("performance_key_1", iacTypes.NewTestMetadata()),
						},
						Encryption: rds.Encryption{
							Metadata:       iacTypes.NewTestMetadata(),
							EncryptStorage: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							KMSKeyID:       iacTypes.String("kms_key_2", iacTypes.NewTestMetadata()),
						},
						PublicAccess:     iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						Engine:           iacTypes.String(rds.EngineAurora, iacTypes.NewTestMetadata()),
						StorageEncrypted: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					},
				},
				Clusters: []rds.Cluster{
					{
						Metadata:                  iacTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: iacTypes.Int(7, iacTypes.NewTestMetadata()),
						ReplicationSourceARN:      iacTypes.String("arn-of-a-source-db-cluster", iacTypes.NewTestMetadata()),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: iacTypes.NewTestMetadata(),
							Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							KMSKeyID: iacTypes.String("", iacTypes.NewTestMetadata()),
						},
						Encryption: rds.Encryption{
							Metadata:       iacTypes.NewTestMetadata(),
							EncryptStorage: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							KMSKeyID:       iacTypes.String("kms_key_1", iacTypes.NewTestMetadata()),
						},
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									Metadata:                  iacTypes.NewTestMetadata(),
									BackupRetentionPeriodDays: iacTypes.Int(0, iacTypes.NewTestMetadata()),
									ReplicationSourceARN:      iacTypes.String("", iacTypes.NewTestMetadata()),
									PerformanceInsights: rds.PerformanceInsights{
										Metadata: iacTypes.NewTestMetadata(),
										Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
										KMSKeyID: iacTypes.String("performance_key_0", iacTypes.NewTestMetadata()),
									},
									Encryption: rds.Encryption{
										Metadata:       iacTypes.NewTestMetadata(),
										EncryptStorage: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
										KMSKeyID:       iacTypes.String("kms_key_0", iacTypes.NewTestMetadata()),
									},
									PublicAccess:     iacTypes.Bool(false, iacTypes.NewTestMetadata()),
									Engine:           iacTypes.String(rds.EngineAurora, iacTypes.NewTestMetadata()),
									StorageEncrypted: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
								},
								ClusterIdentifier: iacTypes.String("aws_rds_cluster.example", iacTypes.NewTestMetadata()),
							},
						},
						PublicAccess: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						Engine:       iacTypes.String(rds.EngineAuroraMysql, iacTypes.NewTestMetadata()),
						AvailabilityZones: iacTypes.StringValueList{
							iacTypes.String("us-west-2a", iacTypes.NewTestMetadata()),
							iacTypes.String("us-west-2b", iacTypes.NewTestMetadata()),
							iacTypes.String("us-west-2c", iacTypes.NewTestMetadata()),
						},
						DeletionProtection: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					},
				},
				Classic: rds.Classic{
					DBSecurityGroups: []rds.DBSecurityGroup{
						{
							Metadata: iacTypes.NewTestMetadata(),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptInstance(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  rds.Instance
	}{
		{
			name: "instance defaults",
			terraform: `
			resource "aws_db_instance" "example" {
			}
`,
			expected: rds.Instance{
				Metadata:                  iacTypes.NewTestMetadata(),
				BackupRetentionPeriodDays: iacTypes.Int(0, iacTypes.NewTestMetadata()),
				ReplicationSourceARN:      iacTypes.String("", iacTypes.NewTestMetadata()),
				PerformanceInsights: rds.PerformanceInsights{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("", iacTypes.NewTestMetadata()),
				},
				Encryption: rds.Encryption{
					Metadata:       iacTypes.NewTestMetadata(),
					EncryptStorage: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					KMSKeyID:       iacTypes.String("", iacTypes.NewTestMetadata()),
				},
				PublicAccess:     iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				Engine:           iacTypes.String(rds.EngineAurora, iacTypes.NewTestMetadata()),
				StorageEncrypted: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				IAMAuthEnabled:   iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstance(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  rds.Cluster
	}{
		{
			name: "cluster defaults",
			terraform: `
			resource "aws_rds_cluster" "example" {
			  }
`,
			expected: rds.Cluster{
				Metadata:                  iacTypes.NewTestMetadata(),
				BackupRetentionPeriodDays: iacTypes.Int(1, iacTypes.NewTestMetadata()),
				ReplicationSourceARN:      iacTypes.String("", iacTypes.NewTestMetadata()),
				PerformanceInsights: rds.PerformanceInsights{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("", iacTypes.NewTestMetadata()),
				},
				Encryption: rds.Encryption{
					Metadata:       iacTypes.NewTestMetadata(),
					EncryptStorage: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					KMSKeyID:       iacTypes.String("", iacTypes.NewTestMetadata()),
				},
				PublicAccess: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				Engine:       iacTypes.String(rds.EngineAurora, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted, _ := adaptCluster(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_rds_cluster" "example" {
		backup_retention_period = 7
		kms_key_id  = "kms_key_1"
		storage_encrypted = true
		replication_source_identifier = "arn-of-a-source-db-cluster"
	  }
	
	resource "aws_rds_cluster_instance" "example" {
		cluster_identifier      = aws_rds_cluster.example.id
		backup_retention_period = 7
		performance_insights_enabled = true
		performance_insights_kms_key_id = "performance_key"
		storage_encrypted = true
		kms_key_id  = "kms_key_0"
	}

	resource "aws_db_security_group" "example" {
	}

	resource "aws_db_instance" "example" {
		publicly_accessible = false
		backup_retention_period = 7
		performance_insights_enabled = true
		performance_insights_kms_key_id = "performance_key"
		storage_encrypted = true
		kms_key_id  = "kms_key_0"
	}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.Instances, 1)

	cluster := adapted.Clusters[0]
	instance := adapted.Instances[0]
	classic := adapted.Classic

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 7, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, cluster.BackupRetentionPeriodDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.BackupRetentionPeriodDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.Encryption.EncryptStorage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.Encryption.EncryptStorage.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.ReplicationSourceARN.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.ReplicationSourceARN.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, cluster.Instances[0].Instance.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, cluster.Instances[0].Instance.Metadata.Range().GetEndLine())

	assert.Equal(t, 2, cluster.Instances[0].ClusterIdentifier.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, cluster.Instances[0].ClusterIdentifier.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, cluster.Instances[0].Instance.BackupRetentionPeriodDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, cluster.Instances[0].Instance.BackupRetentionPeriodDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, cluster.Instances[0].Instance.PerformanceInsights.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, cluster.Instances[0].Instance.PerformanceInsights.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, cluster.Instances[0].Instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, cluster.Instances[0].Instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, cluster.Instances[0].Instance.Encryption.EncryptStorage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, cluster.Instances[0].Instance.Encryption.EncryptStorage.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, cluster.Instances[0].Instance.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, cluster.Instances[0].Instance.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, classic.DBSecurityGroups[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 19, classic.DBSecurityGroups[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 21, instance.Metadata.Range().GetStartLine())
	assert.Equal(t, 28, instance.Metadata.Range().GetEndLine())

	assert.Equal(t, 22, instance.PublicAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, instance.PublicAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, instance.BackupRetentionPeriodDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, instance.BackupRetentionPeriodDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 24, instance.PerformanceInsights.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, instance.PerformanceInsights.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 25, instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, instance.Encryption.EncryptStorage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 26, instance.Encryption.EncryptStorage.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 27, instance.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 27, instance.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
