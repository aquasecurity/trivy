package dynamodb

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/dynamodb"
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
		cluster.Metadata = ssEncryptionBlock.GetMetadata()
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		cluster.ServerSideEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)

		if resource.TypeLabel() == "aws_dynamodb_table" {
			kmsKeyIdAttr := ssEncryptionBlock.GetAttribute("kms_key_arn")

			kmsData, err := module.GetReferencedBlock(kmsKeyIdAttr, resource)
			if err == nil && kmsData.IsNotNil() && kmsData.GetAttribute("key_id").IsNotNil() {
				kmsKeyIdAttr = kmsData.GetAttribute("key_id")
			}

			cluster.ServerSideEncryption.KMSKeyID = kmsKeyIdAttr.AsStringValueOrDefault("alias/aws/dynamodb", ssEncryptionBlock)
		}
	}

	if recoveryBlock := resource.GetBlock("point_in_time_recovery"); recoveryBlock.IsNotNil() {
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		cluster.PointInTimeRecovery = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return cluster
}
