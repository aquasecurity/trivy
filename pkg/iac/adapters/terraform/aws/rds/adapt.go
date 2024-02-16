package rds

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) rds.RDS {
	return rds.RDS{
		Instances:       getInstances(modules),
		Clusters:        getClusters(modules),
		Classic:         getClassic(modules),
		Snapshots:       getSnapshots(modules),
		ParameterGroups: getParameterGroups(modules),
	}
}

func getInstances(modules terraform.Modules) (instances []rds.Instance) {
	for _, resource := range modules.GetResourcesByType("aws_db_instance") {
		instances = append(instances, adaptInstance(resource, modules))
	}

	return instances
}

func getParameterGroups(modules terraform.Modules) (parametergroups []rds.ParameterGroups) {
	for _, resource := range modules.GetResourcesByType("aws_db_parameter_group") {
		parametergroups = append(parametergroups, adaptDBParameterGroups(resource, modules))
	}

	return parametergroups
}

func getSnapshots(modules terraform.Modules) (snapshots []rds.Snapshots) {
	for _, resource := range modules.GetResourcesByType("aws_db_snapshot") {
		snapshots = append(snapshots, adaptDBSnapshots(resource, modules))
	}

	return snapshots
}

func getClusters(modules terraform.Modules) (clusters []rds.Cluster) {

	rdsInstanceMaps := modules.GetChildResourceIDMapByType("aws_rds_cluster_instance")
	for _, resource := range modules.GetResourcesByType("aws_rds_cluster") {
		cluster, instanceIDs := adaptCluster(resource, modules)
		for _, id := range instanceIDs {
			rdsInstanceMaps.Resolve(id)
		}
		clusters = append(clusters, cluster)
	}

	orphanResources := modules.GetResourceByIDs(rdsInstanceMaps.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := rds.Cluster{
			Metadata:                  iacTypes.NewUnmanagedMetadata(),
			BackupRetentionPeriodDays: iacTypes.IntDefault(1, iacTypes.NewUnmanagedMetadata()),
			ReplicationSourceARN:      iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: iacTypes.NewUnmanagedMetadata(),
				Enabled:  iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				KMSKeyID: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			},
			Instances: nil,
			Encryption: rds.Encryption{
				Metadata:       iacTypes.NewUnmanagedMetadata(),
				EncryptStorage: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				KMSKeyID:       iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			},
			PublicAccess:         iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
			Engine:               iacTypes.StringUnresolvable(iacTypes.NewUnmanagedMetadata()),
			LatestRestorableTime: iacTypes.TimeUnresolvable(iacTypes.NewUnmanagedMetadata()),
			DeletionProtection:   iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		}
		for _, orphan := range orphanResources {
			orphanage.Instances = append(orphanage.Instances, adaptClusterInstance(orphan, modules))
		}
		clusters = append(clusters, orphanage)
	}

	return clusters
}

func getClassic(modules terraform.Modules) rds.Classic {
	classic := rds.Classic{
		DBSecurityGroups: nil,
	}
	for _, resource := range modules.GetResourcesByType("aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group") {
		classic.DBSecurityGroups = append(classic.DBSecurityGroups, adaptClassicDBSecurityGroup(resource))
	}
	return classic
}

func adaptClusterInstance(resource *terraform.Block, modules terraform.Modules) rds.ClusterInstance {
	clusterIdAttr := resource.GetAttribute("cluster_identifier")
	clusterId := clusterIdAttr.AsStringValueOrDefault("", resource)

	if clusterIdAttr.IsResourceBlockReference("aws_rds_cluster") {
		if referenced, err := modules.GetReferencedBlock(clusterIdAttr, resource); err == nil {
			clusterId = iacTypes.String(referenced.FullName(), referenced.GetMetadata())
		}
	}

	return rds.ClusterInstance{
		ClusterIdentifier: clusterId,
		Instance:          adaptInstance(resource, modules),
	}
}

func adaptClassicDBSecurityGroup(resource *terraform.Block) rds.DBSecurityGroup {
	return rds.DBSecurityGroup{
		Metadata: resource.GetMetadata(),
	}
}

func adaptInstance(resource *terraform.Block, modules terraform.Modules) rds.Instance {

	var ReadReplicaDBInstanceIdentifiers []iacTypes.StringValue
	rrdiAttr := resource.GetAttribute("replicate_source_db")
	for _, rrdi := range rrdiAttr.AsStringValues() {
		ReadReplicaDBInstanceIdentifiers = append(ReadReplicaDBInstanceIdentifiers, rrdi)
	}

	var TagList []rds.TagList
	tagres := resource.GetBlocks("tags")
	for _, tagres := range tagres {

		TagList = append(TagList, rds.TagList{
			Metadata: tagres.GetMetadata(),
		})
	}

	var EnabledCloudwatchLogsExports []iacTypes.StringValue
	ecweAttr := resource.GetAttribute("enabled_cloudwatch_logs_exports")
	for _, ecwe := range ecweAttr.AsStringValues() {
		EnabledCloudwatchLogsExports = append(EnabledCloudwatchLogsExports, ecwe)
	}

	replicaSource := resource.GetAttribute("replicate_source_db")
	replicaSourceValue := ""
	if replicaSource.IsNotNil() {
		if referenced, err := modules.GetReferencedBlock(replicaSource, resource); err == nil {
			replicaSourceValue = referenced.ID()
		}
	}
	return rds.Instance{
		Metadata:                         resource.GetMetadata(),
		BackupRetentionPeriodDays:        resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		ReplicationSourceARN:             iacTypes.StringExplicit(replicaSourceValue, resource.GetMetadata()),
		PerformanceInsights:              adaptPerformanceInsights(resource),
		Encryption:                       adaptEncryption(resource),
		PublicAccess:                     resource.GetAttribute("publicly_accessible").AsBoolValueOrDefault(false, resource),
		Engine:                           resource.GetAttribute("engine").AsStringValueOrDefault(rds.EngineAurora, resource),
		IAMAuthEnabled:                   resource.GetAttribute("iam_database_authentication_enabled").AsBoolValueOrDefault(false, resource),
		DeletionProtection:               resource.GetAttribute("deletion_protection").AsBoolValueOrDefault(false, resource),
		DBInstanceArn:                    resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
		StorageEncrypted:                 resource.GetAttribute("storage_encrypted").AsBoolValueOrDefault(true, resource),
		DBInstanceIdentifier:             resource.GetAttribute("identifier").AsStringValueOrDefault("", resource),
		EngineVersion:                    resource.GetAttribute("engine_version").AsStringValueOrDefault("", resource),
		AutoMinorVersionUpgrade:          resource.GetAttribute("auto_minor_version_upgrade").AsBoolValueOrDefault(false, resource),
		MultiAZ:                          resource.GetAttribute("multi_az").AsBoolValueOrDefault(false, resource),
		PubliclyAccessible:               resource.GetAttribute("publicly_accessible").AsBoolValueOrDefault(false, resource),
		LatestRestorableTime:             iacTypes.TimeUnresolvable(resource.GetMetadata()),
		ReadReplicaDBInstanceIdentifiers: ReadReplicaDBInstanceIdentifiers,
		TagList:                          TagList,
		EnabledCloudwatchLogsExports:     EnabledCloudwatchLogsExports,
	}
}

func adaptDBParameterGroups(resource *terraform.Block, modules terraform.Modules) rds.ParameterGroups {

	var Parameters []rds.Parameters
	paramres := resource.GetBlocks("parameter")
	for _, paramres := range paramres {

		Parameters = append(Parameters, rds.Parameters{
			Metadata:       paramres.GetMetadata(),
			ParameterName:  iacTypes.StringDefault("", paramres.GetMetadata()),
			ParameterValue: iacTypes.StringDefault("", paramres.GetMetadata()),
		})
	}

	return rds.ParameterGroups{
		Metadata:               resource.GetMetadata(),
		DBParameterGroupName:   resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		DBParameterGroupFamily: resource.GetAttribute("family").AsStringValueOrDefault("", resource),
		Parameters:             Parameters,
	}
}

func adaptDBSnapshots(resource *terraform.Block, modules terraform.Modules) rds.Snapshots {

	return rds.Snapshots{
		Metadata:             resource.GetMetadata(),
		DBSnapshotIdentifier: resource.GetAttribute("db_snapshot_identifier").AsStringValueOrDefault("", resource),
		DBSnapshotArn:        resource.GetAttribute("db_snapshot_arn").AsStringValueOrDefault("", resource),
		Encrypted:            resource.GetAttribute("encrypted").AsBoolValueOrDefault(true, resource),
		KmsKeyId:             resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
		SnapshotAttributes:   nil,
	}
}

func adaptCluster(resource *terraform.Block, modules terraform.Modules) (rds.Cluster, []string) {

	clusterInstances, ids := getClusterInstances(resource, modules)

	var public bool
	for _, instance := range clusterInstances {
		if instance.PublicAccess.IsTrue() {
			public = true
			break
		}
	}

	return rds.Cluster{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(1, resource),
		ReplicationSourceARN:      resource.GetAttribute("replication_source_identifier").AsStringValueOrDefault("", resource),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Instances:                 clusterInstances,
		Encryption:                adaptEncryption(resource),
		PublicAccess:              iacTypes.Bool(public, resource.GetMetadata()),
		Engine:                    resource.GetAttribute("engine").AsStringValueOrDefault(rds.EngineAurora, resource),
		LatestRestorableTime:      iacTypes.TimeUnresolvable(resource.GetMetadata()),
		AvailabilityZones:         resource.GetAttribute("availability_zones").AsStringValueSliceOrEmpty(),
		DeletionProtection:        resource.GetAttribute("deletion_protection").AsBoolValueOrDefault(false, resource),
	}, ids
}

func getClusterInstances(resource *terraform.Block, modules terraform.Modules) (clusterInstances []rds.ClusterInstance, instanceIDs []string) {
	clusterInstanceResources := modules.GetReferencingResources(resource, "aws_rds_cluster_instance", "cluster_identifier")

	for _, ciResource := range clusterInstanceResources {
		instanceIDs = append(instanceIDs, ciResource.ID())
		clusterInstances = append(clusterInstances, adaptClusterInstance(ciResource, modules))
	}
	return clusterInstances, instanceIDs
}

func adaptPerformanceInsights(resource *terraform.Block) rds.PerformanceInsights {
	return rds.PerformanceInsights{
		Metadata: resource.GetMetadata(),
		Enabled:  resource.GetAttribute("performance_insights_enabled").AsBoolValueOrDefault(false, resource),
		KMSKeyID: resource.GetAttribute("performance_insights_kms_key_id").AsStringValueOrDefault("", resource),
	}
}

func adaptEncryption(resource *terraform.Block) rds.Encryption {
	return rds.Encryption{
		Metadata:       resource.GetMetadata(),
		EncryptStorage: resource.GetAttribute("storage_encrypted").AsBoolValueOrDefault(false, resource),
		KMSKeyID:       resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
	}
}
