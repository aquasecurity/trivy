package documentdb

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) documentdb.DocumentDB {
	return documentdb.DocumentDB{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []documentdb.Cluster {
	var clusters []documentdb.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_docdb_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block, module *terraform.Module) documentdb.Cluster {
	identifierAttr := resource.GetAttribute("cluster_identifier")
	identifierVal := identifierAttr.AsStringValue()

	var enabledLogExports []types.StringValue
	var instances []documentdb.Instance

	enabledLogExportsAttr := resource.GetAttribute("enabled_cloudwatch_logs_exports")
	for _, logExport := range enabledLogExportsAttr.AsStringValues() {
		enabledLogExports = append(enabledLogExports, logExport)
	}

	instancesRes := module.GetReferencingResources(resource, "aws_docdb_cluster_instance", "cluster_identifier")
	for _, instanceRes := range instancesRes {
		keyIDAttr := instanceRes.GetAttribute("kms_key_id")
		keyIDVal := keyIDAttr.AsStringValue()

		instances = append(instances, documentdb.Instance{
			Metadata: instanceRes.GetMetadata(),
			KMSKeyID: keyIDVal,
		})
	}

	storageEncryptedAttr := resource.GetAttribute("storage_encrypted")
	storageEncryptedVal := storageEncryptedAttr.AsBoolValue()

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValue()

	return documentdb.Cluster{
		Metadata:              resource.GetMetadata(),
		Identifier:            identifierVal,
		EnabledLogExports:     enabledLogExports,
		BackupRetentionPeriod: resource.GetAttribute("backup_retention_period").AsIntValue(),
		Instances:             instances,
		StorageEncrypted:      storageEncryptedVal,
		KMSKeyID:              KMSKeyIDVal,
	}
}
