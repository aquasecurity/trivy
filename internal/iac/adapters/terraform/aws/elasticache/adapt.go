package elasticache

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) elasticache.ElastiCache {
	return elasticache.ElastiCache{
		Clusters:          adaptClusters(modules),
		ReplicationGroups: adaptReplicationGroups(modules),
		SecurityGroups:    adaptSecurityGroups(modules),
	}
}
func adaptClusters(modules terraform.Modules) []elasticache.Cluster {
	var clusters []elasticache.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticache_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptReplicationGroups(modules terraform.Modules) []elasticache.ReplicationGroup {
	var replicationGroups []elasticache.ReplicationGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticache_replication_group") {
			replicationGroups = append(replicationGroups, adaptReplicationGroup(resource))
		}
	}
	return replicationGroups
}

func adaptSecurityGroups(modules terraform.Modules) []elasticache.SecurityGroup {
	var securityGroups []elasticache.SecurityGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticache_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource))
		}
	}
	return securityGroups
}

func adaptCluster(resource *terraform.Block) elasticache.Cluster {
	engineAttr := resource.GetAttribute("engine")
	engineVal := engineAttr.AsStringValueOrDefault("", resource)

	nodeTypeAttr := resource.GetAttribute("node_type")
	nodeTypeVal := nodeTypeAttr.AsStringValueOrDefault("", resource)

	snapshotRetentionAttr := resource.GetAttribute("snapshot_retention_limit")
	snapshotRetentionVal := snapshotRetentionAttr.AsIntValueOrDefault(0, resource)

	return elasticache.Cluster{
		Metadata:               resource.GetMetadata(),
		Engine:                 engineVal,
		NodeType:               nodeTypeVal,
		SnapshotRetentionLimit: snapshotRetentionVal,
	}
}

func adaptReplicationGroup(resource *terraform.Block) elasticache.ReplicationGroup {
	transitEncryptionAttr := resource.GetAttribute("transit_encryption_enabled")
	transitEncryptionVal := transitEncryptionAttr.AsBoolValueOrDefault(false, resource)

	atRestEncryptionAttr := resource.GetAttribute("at_rest_encryption_enabled")
	atRestEncryptionVal := atRestEncryptionAttr.AsBoolValueOrDefault(false, resource)

	return elasticache.ReplicationGroup{
		Metadata:                 resource.GetMetadata(),
		TransitEncryptionEnabled: transitEncryptionVal,
		AtRestEncryptionEnabled:  atRestEncryptionVal,
	}
}

func adaptSecurityGroup(resource *terraform.Block) elasticache.SecurityGroup {
	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	return elasticache.SecurityGroup{
		Metadata:    resource.GetMetadata(),
		Description: descriptionVal,
	}
}
