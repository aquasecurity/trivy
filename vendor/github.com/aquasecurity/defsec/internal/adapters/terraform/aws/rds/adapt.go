package rds

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) rds.RDS {
	return rds.RDS{
		Instances: getInstances(modules),
		Clusters:  getClusters(modules),
		Classic:   getClassic(modules),
	}
}

func getInstances(modules terraform.Modules) (instances []rds.Instance) {
	for _, resource := range modules.GetResourcesByType("aws_db_instance") {
		instances = append(instances, adaptInstance(resource, modules))
	}

	return instances
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
			Metadata:                  types.NewUnmanagedMetadata(),
			BackupRetentionPeriodDays: types.IntDefault(1, types.NewUnmanagedMetadata()),
			ReplicationSourceARN:      types.StringDefault("", types.NewUnmanagedMetadata()),
			PerformanceInsights: rds.PerformanceInsights{
				Metadata: types.NewUnmanagedMetadata(),
				Enabled:  types.BoolDefault(false, types.NewUnmanagedMetadata()),
				KMSKeyID: types.StringDefault("", types.NewUnmanagedMetadata()),
			},
			Instances: nil,
			Encryption: rds.Encryption{
				Metadata:       types.NewUnmanagedMetadata(),
				EncryptStorage: types.BoolDefault(false, types.NewUnmanagedMetadata()),
				KMSKeyID:       types.StringDefault("", types.NewUnmanagedMetadata()),
			},
		}
		for _, orphan := range orphanResources {
			orphanage.Instances = append(orphanage.Instances, adaptClusterInstance(orphan, modules))
		}
		clusters = append(clusters, orphanage)
	}

	return clusters
}

func getClassic(modules terraform.Modules) (classic rds.Classic) {

	var classicSecurityGroups []rds.DBSecurityGroup

	for _, resource := range modules.GetResourcesByType("aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group") {
		classicSecurityGroups = append(classicSecurityGroups, adaptClassicDBSecurityGroup(resource))
	}

	classic.DBSecurityGroups = classicSecurityGroups
	return classic
}

func adaptClusterInstance(resource *terraform.Block, modules terraform.Modules) rds.ClusterInstance {
	clusterIdAttr := resource.GetAttribute("cluster_identifier")
	clusterId := clusterIdAttr.AsStringValueOrDefault("", resource)

	if clusterIdAttr.IsResourceBlockReference("aws_rds_cluster") {
		if referenced, err := modules.GetReferencedBlock(clusterIdAttr, resource); err == nil {
			clusterId = types.String(referenced.FullName(), referenced.GetMetadata())
		}
	}

	return rds.ClusterInstance{
		Metadata:          resource.GetMetadata(),
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
	replicaSource := resource.GetAttribute("replicate_source_db")
	replicaSourceValue := ""
	if replicaSource.IsNotNil() {
		if referenced, err := modules.GetReferencedBlock(replicaSource, resource); err == nil {
			replicaSourceValue = referenced.ID()
		}
	}
	return rds.Instance{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		ReplicationSourceARN:      types.StringExplicit(replicaSourceValue, resource.GetMetadata()),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Encryption:                adaptEncryption(resource),
		PublicAccess:              resource.GetAttribute("publicly_accessible").AsBoolValueOrDefault(false, resource),
	}
}

func adaptCluster(resource *terraform.Block, modules terraform.Modules) (rds.Cluster, []string) {

	clusterInstances, ids := getClusterInstances(resource, modules)

	return rds.Cluster{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(1, resource),
		ReplicationSourceARN:      resource.GetAttribute("replication_source_identifier").AsStringValueOrDefault("", resource),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Instances:                 clusterInstances,
		Encryption:                adaptEncryption(resource),
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
