package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getClustersAndInstances(ctx parser.FileContext) (clusters []rds.Cluster, orphans []rds.Instance) {

	clusterMap := getClusters(ctx)

	for _, r := range ctx.GetResourcesByType("AWS::RDS::DBInstance") {

		instance := rds.Instance{
			Metadata:                  r.Metadata(),
			BackupRetentionPeriodDays: r.GetIntProperty("BackupRetentionPeriod", 1),
			ReplicationSourceARN:      r.GetStringProperty("SourceDBInstanceIdentifier"),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: r.Metadata(),
				Enabled:  r.GetBoolProperty("EnablePerformanceInsights"),
				KMSKeyID: r.GetStringProperty("PerformanceInsightsKMSKeyId"),
			},
			Encryption: rds.Encryption{
				Metadata:       r.Metadata(),
				EncryptStorage: r.GetBoolProperty("StorageEncrypted"),
				KMSKeyID:       r.GetStringProperty("KmsKeyId"),
			},
			PublicAccess: r.GetBoolProperty("PubliclyAccessible", true),
		}

		if clusterID := r.GetProperty("DBClusterIdentifier"); clusterID.IsString() {
			var found bool
			for key, cluster := range clusterMap {
				if key == clusterID.AsString() {
					cluster.Instances = append(cluster.Instances, rds.ClusterInstance{
						Metadata:          r.Metadata(),
						Instance:          instance,
						ClusterIdentifier: clusterID.AsStringValue(),
					})
					clusterMap[key] = cluster
					found = true
					break
				}
			}
			if found {
				continue
			}
		}

		orphans = append(orphans, instance)
	}

	for _, cluster := range clusterMap {
		clusters = append(clusters, cluster)
	}

	return clusters, orphans
}
