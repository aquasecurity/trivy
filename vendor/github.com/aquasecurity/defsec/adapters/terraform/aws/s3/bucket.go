package s3

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/s3"
)

type adapter struct {
	modules   terraform.Modules
	bucketMap map[string]s3.Bucket
}

func (a *adapter) adaptBuckets() []s3.Bucket {
	for _, block := range a.modules.GetResourcesByType("aws_s3_bucket") {
		bucket := s3.Bucket{
			Name:     block.GetAttribute("bucket").AsStringValueOrDefault("", block),
			Metadata: block.GetMetadata(),
			Versioning: s3.Versioning{
				Metadata: block.GetMetadata(),
				Enabled:  isVersioned(block),
			},
			Encryption: s3.Encryption{
				Metadata: block.GetMetadata(),
				Enabled:  isEncrypted(block),
				KMSKeyId: block.GetNestedAttribute("server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.kms_master_key_id").AsStringValueOrDefault("", block),
			},
			Logging: s3.Logging{
				Metadata: block.GetMetadata(),
				Enabled:  hasLogging(block),
			},
			ACL: block.GetAttribute("acl").AsStringValueOrDefault("", block),
		}
		a.bucketMap[block.ID()] = bucket
	}

	a.adaptPublicAccessBlocks()

	var buckets []s3.Bucket
	for _, bucket := range a.bucketMap {
		buckets = append(buckets, bucket)
	}

	return buckets
}

func isEncrypted(b *terraform.Block) types.BoolValue {
	encryptionBlock := b.GetBlock("server_side_encryption_configuration")
	if encryptionBlock.IsNil() {
		return types.BoolDefault(false, b.GetMetadata())
	}
	ruleBlock := encryptionBlock.GetBlock("rule")
	if ruleBlock.IsNil() {
		return types.BoolDefault(false, encryptionBlock.GetMetadata())
	}
	defaultBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
	if defaultBlock.IsNil() {
		return types.BoolDefault(false, ruleBlock.GetMetadata())
	}
	sseAlgorithm := defaultBlock.GetAttribute("sse_algorithm")
	if sseAlgorithm.IsNil() {
		return types.BoolDefault(false, defaultBlock.GetMetadata())
	}
	return types.Bool(
		true,
		sseAlgorithm.GetMetadata(),
	)
}

func hasLogging(b *terraform.Block) types.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if targetAttr := loggingBlock.GetAttribute("target_bucket"); targetAttr.IsNotNil() && targetAttr.IsNotEmpty() {
			return types.Bool(true, targetAttr.GetMetadata())
		}
		return types.BoolDefault(false, loggingBlock.GetMetadata())
	}
	return types.BoolDefault(false, b.GetMetadata())
}

func isVersioned(b *terraform.Block) types.BoolValue {
	if versioningBlock := b.GetBlock("versioning"); versioningBlock.IsNotNil() {
		return versioningBlock.GetAttribute("enabled").AsBoolValueOrDefault(true, versioningBlock)
	}
	return types.BoolDefault(
		false,
		b.GetMetadata(),
	)
}
