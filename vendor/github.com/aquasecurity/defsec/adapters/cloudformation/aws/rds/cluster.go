package rds

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/rds"
)

func getClusters(ctx parser.FileContext) (clusters map[string]rds.Cluster) {
	clusters = make(map[string]rds.Cluster)
	for _, clusterResource := range ctx.GetResourceByType("AWS::RDS::DBCluster") {
		var cluster rds.Cluster
		cluster.Metadata = clusterResource.Metadata()
		if backupProp := clusterResource.GetProperty("BackupRetentionPeriod"); backupProp.IsInt() {
			cluster.BackupRetentionPeriodDays = backupProp.AsIntValue()
		} else {
			cluster.BackupRetentionPeriodDays = types.IntDefault(1, clusterResource.Metadata())
		}

		if replicaProp := clusterResource.GetProperty("SourceDBInstanceIdentifier"); replicaProp.IsString() {
			cluster.ReplicationSourceARN = replicaProp.AsStringValue()
		} else {
			cluster.ReplicationSourceARN = types.StringDefault("", clusterResource.Metadata())
		}

		if piProp := clusterResource.GetProperty("EnablePerformanceInsights"); piProp.IsBool() {
			cluster.PerformanceInsights.Enabled = piProp.AsBoolValue()
		} else {
			cluster.PerformanceInsights.Enabled = types.BoolDefault(false, clusterResource.Metadata())
		}

		if insightsKeyProp := clusterResource.GetProperty("PerformanceInsightsKMSKeyId"); insightsKeyProp.IsString() {
			cluster.PerformanceInsights.KMSKeyID = insightsKeyProp.AsStringValue()
		} else {
			cluster.PerformanceInsights.KMSKeyID = types.StringDefault("", clusterResource.Metadata())
		}

		if encryptedProp := clusterResource.GetProperty("StorageEncrypted"); encryptedProp.IsBool() {
			cluster.Encryption.EncryptStorage = encryptedProp.AsBoolValue()
		} else {
			cluster.Encryption.EncryptStorage = types.BoolDefault(false, clusterResource.Metadata())
		}

		if keyProp := clusterResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			cluster.Encryption.KMSKeyID = keyProp.AsStringValue()
		} else {
			cluster.Encryption.KMSKeyID = types.StringDefault("", clusterResource.Metadata())
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
	for _, dbsgResource := range ctx.GetResourceByType("AWS::RDS::DBSecurityGroup") {
		var group rds.DBSecurityGroup
		group.Metadata = dbsgResource.Metadata()
		groups = append(groups, group)
	}
	return groups
}
