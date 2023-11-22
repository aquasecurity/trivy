package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

func getClusters(ctx parser.FileContext) (clusters map[string]rds.Cluster) {
	clusters = make(map[string]rds.Cluster)
	for _, clusterResource := range ctx.GetResourcesByType("AWS::RDS::DBCluster") {
		cluster := rds.Cluster{
			Metadata:                  clusterResource.Metadata(),
			BackupRetentionPeriodDays: defsecTypes.IntDefault(1, clusterResource.Metadata()),
			ReplicationSourceARN:      defsecTypes.StringDefault("", clusterResource.Metadata()),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: clusterResource.Metadata(),
				Enabled:  defsecTypes.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID: defsecTypes.StringDefault("", clusterResource.Metadata()),
			},
			Instances: nil,
			Encryption: rds.Encryption{
				Metadata:       clusterResource.Metadata(),
				EncryptStorage: defsecTypes.BoolDefault(false, clusterResource.Metadata()),
				KMSKeyID:       defsecTypes.StringDefault("", clusterResource.Metadata()),
			},
			PublicAccess:         defsecTypes.BoolDefault(false, clusterResource.Metadata()),
			Engine:               defsecTypes.StringDefault(rds.EngineAurora, clusterResource.Metadata()),
			LatestRestorableTime: defsecTypes.TimeUnresolvable(clusterResource.Metadata()),
			DeletionProtection:   defsecTypes.BoolDefault(false, clusterResource.Metadata()),
		}

		if engineProp := clusterResource.GetProperty("Engine"); engineProp.IsString() {
			cluster.Engine = engineProp.AsStringValue()
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
		group := rds.DBSecurityGroup{
			Metadata: dbsgResource.Metadata(),
		}
		groups = append(groups, group)
	}
	return groups
}
