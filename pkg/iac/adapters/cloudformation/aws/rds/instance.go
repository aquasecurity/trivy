package rds

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getClustersAndInstances(ctx parser.FileContext) ([]rds.Cluster, []rds.Instance) {

	clusterMap := getClusters(ctx)

	var orphans []rds.Instance

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
			if cluster, exist := clusterMap[clusterID.AsString()]; exist {
				cluster.Instances = append(cluster.Instances, rds.ClusterInstance{
					Instance:          instance,
					ClusterIdentifier: clusterID.AsStringValue(),
				})
				clusterMap[clusterID.AsString()] = cluster
			}
		} else {
			orphans = append(orphans, instance)
		}
	}

	clusters := make([]rds.Cluster, 0, len(clusterMap))

	for _, cluster := range clusterMap {
		clusters = append(clusters, cluster)
	}

	return clusters, orphans
}

func getDBParameterGroups(ctx parser.FileContext, r *parser.Resource) (dbParameterGroup []rds.DBParameterGroupsList) {

	var parameterGroupList []rds.DBParameterGroupsList

	dbParameterGroupName := r.GetStringProperty("DBParameterGroupName")

	for _, r := range ctx.GetResourcesByType("AWS::RDS::DBParameterGroup") {
		name := r.GetStringProperty("DBParameterGroupName")
		// TODO: find by resource logical id
		if !dbParameterGroupName.EqualTo(name.Value()) {
			continue
		}
		dbpmgl := rds.DBParameterGroupsList{
			Metadata:             r.Metadata(),
			DBParameterGroupName: name,
			KMSKeyID:             types.StringUnresolvable(r.Metadata()),
		}
		parameterGroupList = append(dbParameterGroup, dbpmgl)
	}

	return parameterGroupList
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
	tagLists := r.GetProperty("Tags")

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
	readReplicaDBIdentifier := r.GetProperty("SourceDBInstanceIdentifier")

	if readReplicaDBIdentifier.IsNil() || readReplicaDBIdentifier.IsNotList() {
		return readreplicadbidentifier
	}

	for _, rr := range readReplicaDBIdentifier.AsList() {
		readreplicadbidentifier = append(readreplicadbidentifier, rr.AsStringValue())
	}
	return readreplicadbidentifier
}
