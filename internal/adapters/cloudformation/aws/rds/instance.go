package rds

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
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
			PublicAccess:                     r.GetBoolProperty("PubliclyAccessible", true),
			Engine:                           r.GetStringProperty("Engine"),
			IAMAuthEnabled:                   r.GetBoolProperty("EnableIAMDatabaseAuthentication"),
			DeletionProtection:               r.GetBoolProperty("DeletionProtection", false),
			DBInstanceArn:                    r.GetStringProperty("DBInstanceArn"),
			StorageEncrypted:                 r.GetBoolProperty("StorageEncrypted", false),
			DBInstanceIdentifier:             r.GetStringProperty("DBInstanceIdentifier"),
			DBParameterGroups:                getDBParameterGroups(ctx, r),
			TagList:                          getTagList(r),
			EnabledCloudwatchLogsExports:     getEnabledCloudwatchLogsExports(r),
			EngineVersion:                    r.GetStringProperty("EngineVersion"),
			AutoMinorVersionUpgrade:          r.GetBoolProperty("AutoMinorVersionUpgrade"),
			MultiAZ:                          r.GetBoolProperty("MultiAZ"),
			PubliclyAccessible:               r.GetBoolProperty("PubliclyAccessible"),
			LatestRestorableTime:             types.TimeUnresolvable(r.Metadata()),
			ReadReplicaDBInstanceIdentifiers: getReadReplicaDBInstanceIdentifiers(r),
		}

		if clusterID := r.GetProperty("DBClusterIdentifier"); clusterID.IsString() {
			var found bool
			for key, cluster := range clusterMap {
				if key == clusterID.AsString() {
					cluster.Instances = append(cluster.Instances, rds.ClusterInstance{
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

func getDBParameterGroups(ctx parser.FileContext, r *parser.Resource) (dbParameterGroup []rds.DBParameterGroupsList) {

	for _, r := range ctx.GetResourcesByType("DBParameterGroups") {
		dbpmgl := rds.DBParameterGroupsList{
			Metadata:             r.Metadata(),
			DBParameterGroupName: r.GetStringProperty("DBParameterGroupName"),
			KMSKeyID:             types.StringUnresolvable(r.Metadata()),
		}
		dbParameterGroup = append(dbParameterGroup, dbpmgl)
	}

	return dbParameterGroup
}

func getEnabledCloudwatchLogsExports(r *parser.Resource) (enabledcloudwatchlogexportslist []types.StringValue) {
	enabledCloudwatchLogExportList := r.GetProperty("EnableCloudwatchLogsExports")

	if enabledCloudwatchLogExportList.IsNil() || enabledCloudwatchLogExportList.IsNotList() {
		return enabledcloudwatchlogexportslist
	}

	for _, ecle := range enabledCloudwatchLogExportList.AsList() {
		enabledcloudwatchlogexportslist = append(enabledcloudwatchlogexportslist, ecle.AsStringValue())
	}
	return enabledcloudwatchlogexportslist
}

func getTagList(r *parser.Resource) (taglist []rds.TagList) {
	tagLists := r.GetProperty("tags")

	if tagLists.IsNil() || tagLists.IsNotList() {
		return taglist
	}

	for _, tl := range tagLists.AsList() {
		taglist = append(taglist, rds.TagList{
			Metadata: tl.Metadata(),
		})
	}
	return taglist
}

func getReadReplicaDBInstanceIdentifiers(r *parser.Resource) (readreplicadbidentifier []types.StringValue) {
	readReplicaDBIdentifier := r.GetProperty("EnableCloudwatchLogsExports")

	if readReplicaDBIdentifier.IsNil() || readReplicaDBIdentifier.IsNotList() {
		return readreplicadbidentifier
	}

	for _, rr := range readReplicaDBIdentifier.AsList() {
		readreplicadbidentifier = append(readreplicadbidentifier, rr.AsStringValue())
	}
	return readreplicadbidentifier
}
