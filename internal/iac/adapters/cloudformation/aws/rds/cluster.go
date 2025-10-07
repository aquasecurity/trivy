package rds

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getClusters(ctx parser.FileContext) (clusters map[string]rds.Cluster) {
	clusters = make(map[string]rds.Cluster)
	for _, clusterResource := range ctx.GetResourcesByType("AWS::RDS::DBCluster") {
		clusters[clusterResource.ID()] = rds.Cluster{
			Metadata:                  clusterResource.Metadata(),
			BackupRetentionPeriodDays: clusterResource.GetIntProperty("BackupRetentionPeriod", 1),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: clusterResource.Metadata(),
				Enabled:  clusterResource.GetBoolProperty("PerformanceInsightsEnabled"),
				KMSKeyID: clusterResource.GetStringProperty("PerformanceInsightsKmsKeyId"),
			},
			Encryption: rds.Encryption{
				Metadata:       clusterResource.Metadata(),
				EncryptStorage: clusterResource.GetBoolProperty("StorageEncrypted"),
				KMSKeyID:       clusterResource.GetStringProperty("KmsKeyId"),
			},
			PublicAccess:         iacTypes.BoolDefault(false, clusterResource.Metadata()),
			Engine:               clusterResource.GetStringProperty("Engine", rds.EngineAurora),
			LatestRestorableTime: iacTypes.TimeUnresolvable(clusterResource.Metadata()),
			DeletionProtection:   clusterResource.GetBoolProperty("DeletionProtection"),
		}
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
