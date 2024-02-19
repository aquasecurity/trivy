package dynamodb

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{
		DAXClusters: adaptClusters(modules),
		Tables:      adaptTables(modules),
	}
}

func adaptClusters(modules terraform.Modules) []dynamodb.DAXCluster {
	var clusters []dynamodb.DAXCluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_dax_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptTables(modules terraform.Modules) []dynamodb.Table {
	var tables []dynamodb.Table
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_dynamodb_table") {
			tables = append(tables, adaptTable(resource, module))
		}
	}
	return tables
}

func adaptCluster(resource *terraform.Block, module *terraform.Module) dynamodb.DAXCluster {

	cluster := dynamodb.DAXCluster{
		Metadata: resource.GetMetadata(),
		ServerSideEncryption: dynamodb.ServerSideEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: iacTypes.StringDefault("", resource.GetMetadata()),
		},
		PointInTimeRecovery: iacTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if ssEncryptionBlock := resource.GetBlock("server_side_encryption"); ssEncryptionBlock.IsNotNil() {
		cluster.ServerSideEncryption.Metadata = ssEncryptionBlock.GetMetadata()
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		cluster.ServerSideEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)
	}

	if recoveryBlock := resource.GetBlock("point_in_time_recovery"); recoveryBlock.IsNotNil() {
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		cluster.PointInTimeRecovery = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return cluster
}

func adaptTable(resource *terraform.Block, module *terraform.Module) dynamodb.Table {

	table := dynamodb.Table{
		Metadata: resource.GetMetadata(),
		ServerSideEncryption: dynamodb.ServerSideEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: iacTypes.StringDefault("", resource.GetMetadata()),
		},
		PointInTimeRecovery: iacTypes.BoolDefault(false, resource.GetMetadata()),
	}

	if ssEncryptionBlock := resource.GetBlock("server_side_encryption"); ssEncryptionBlock.IsNotNil() {
		table.ServerSideEncryption.Metadata = ssEncryptionBlock.GetMetadata()
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		table.ServerSideEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)

		kmsKeyIdAttr := ssEncryptionBlock.GetAttribute("kms_key_arn")
		table.ServerSideEncryption.KMSKeyID = kmsKeyIdAttr.AsStringValueOrDefault("alias/aws/dynamodb", ssEncryptionBlock)

		kmsBlock, err := module.GetReferencedBlock(kmsKeyIdAttr, resource)
		if err == nil && kmsBlock.IsNotNil() {
			table.ServerSideEncryption.KMSKeyID = iacTypes.String(kmsBlock.FullName(), kmsBlock.GetMetadata())
		}
	}

	if recoveryBlock := resource.GetBlock("point_in_time_recovery"); recoveryBlock.IsNotNil() {
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		table.PointInTimeRecovery = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return table
}
