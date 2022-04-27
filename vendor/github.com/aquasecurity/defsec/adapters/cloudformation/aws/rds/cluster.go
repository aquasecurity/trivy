package rds

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/rds"
)

func getClusters(ctx parser.FileContext) (clusters map[string]rds.Cluster) {
	clusters = make(map[string]rds.Cluster)
	for _, clusterResource := range ctx.GetResourcesByType("AWS::RDS::DBCluster") {
		cluster := rds.Cluster{
			Metadata:                  clusterResource.Metadata(),
			BackupRetentionPeriodDays: types.IntDefault(1, clusterResource.Metadata()),
			ReplicationSourceARN:      types.StringDefault("", clusterResource.Metadata()),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: clusterResource.Metadata(),
				Enabled:  types.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID: types.StringDefault("", clusterResource.Metadata()),
			},
			Instances: nil,
			Encryption: rds.Encryption{
				Metadata:       clusterResource.Metadata(),
				EncryptStorage: types.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID:       types.StringDefault("", clusterResource.Metadata()),
			},
		}

		if backupProp := clusterResource.GetProperty("BackupRetentionPeriod"); backupProp.IsInt() {
			cluster.BackupRetentionPeriodDays = backupProp.AsIntValue()
		}

		if replicaProp := clusterResource.GetProperty("SourceDBInstanceIdentifier"); replicaProp.IsString() {
			cluster.ReplicationSourceARN = replicaProp.AsStringValue()
		}

		if piProp := clusterResource.GetProperty("EnablePerformanceInsights"); piProp.IsBool() {
			cluster.PerformanceInsights.Enabled = piProp.AsBoolValue()
		}

		if insightsKeyProp := clusterResource.GetProperty("PerformanceInsightsKMSKeyId"); insightsKeyProp.IsString() {
			cluster.PerformanceInsights.KMSKeyID = insightsKeyProp.AsStringValue()
		}

		if encryptedProp := clusterResource.GetProperty("StorageEncrypted"); encryptedProp.IsBool() {
			cluster.Encryption.EncryptStorage = encryptedProp.AsBoolValue()
		}

		if keyProp := clusterResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			cluster.Encryption.KMSKeyID = keyProp.AsStringValue()
		}

		clusters[clusterResource.ID()] = cluster
	}
	return clusters
}

func getClassic(ctx parser.FileContext) rds.Classic {
	return rds.Classic{
		DBSecurityGroups: getClassicSecurityGroups(ctx),
	}
}

func getClassicSecurityGroups(ctx parser.FileContext) (groups []rds.DBSecurityGroup) {
	for _, dbsgResource := range ctx.GetResourcesByType("AWS::RDS::DBSecurityGroup") {
		var group rds.DBSecurityGroup
		group.Metadata = dbsgResource.Metadata()
		groups = append(groups, group)
	}
	return groups
}
