package dynamodb

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{
		DAXClusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []dynamodb.DAXCluster {
	var clusters []dynamodb.DAXCluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_dax_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
		for _, resource := range module.GetResourcesByType("aws_dynamodb_table") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block, module *terraform.Module) dynamodb.DAXCluster {

	cluster := dynamodb.DAXCluster{
		Metadata: resource.GetMetadata(),
		ServerSideEncryption: dynamodb.ServerSideEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: types.StringDefault("", resource.GetMetadata()),
		},
		PointInTimeRecovery: types.BoolDefault(false, resource.GetMetadata()),
	}

	if ssEncryptionBlock := resource.GetBlock("server_side_encryption"); ssEncryptionBlock.IsNotNil() {
		cluster.ServerSideEncryption.Metadata = ssEncryptionBlock.GetMetadata()
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		cluster.ServerSideEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)

		if resource.TypeLabel() == "aws_dynamodb_table" {
			kmsKeyIdAttr := ssEncryptionBlock.GetAttribute("kms_key_arn")
			cluster.ServerSideEncryption.KMSKeyID = kmsKeyIdAttr.AsStringValueOrDefault("alias/aws/dynamodb", ssEncryptionBlock)

			kmsBlock, err := module.GetReferencedBlock(kmsKeyIdAttr, resource)
			if err == nil && kmsBlock.IsNotNil() {
				cluster.ServerSideEncryption.KMSKeyID = types.String(kmsBlock.FullName(), kmsBlock.GetMetadata())
			}
		}
	}

	if recoveryBlock := resource.GetBlock("point_in_time_recovery"); recoveryBlock.IsNotNil() {
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		cluster.PointInTimeRecovery = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return cluster
}
