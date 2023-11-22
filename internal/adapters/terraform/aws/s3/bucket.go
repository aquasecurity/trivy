package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type adapter struct {
	modules   terraform.Modules
	bucketMap map[string]*s3.Bucket
}

func (a *adapter) adaptBuckets() []s3.Bucket {
	for _, block := range a.modules.GetResourcesByType("aws_s3_bucket") {
		bucket := &s3.Bucket{
			Metadata:                      block.GetMetadata(),
			Name:                          block.GetAttribute("bucket").AsStringValueOrDefault("", block),
			PublicAccessBlock:             nil,
			BucketPolicies:                nil,
			Encryption:                    getEncryption(block, a),
			Versioning:                    getVersioning(block, a),
			Logging:                       getLogging(block, a),
			ACL:                           getBucketAcl(block, a),
			AccelerateConfigurationStatus: getAccelerateStatus(block, a),
			BucketLocation:                block.GetAttribute("region").AsStringValueOrDefault("", block),
			LifecycleConfiguration:        getLifecycle(block, a),
			Website:                       getWebsite(block, a),
			Objects:                       getObject(block, a),
		}
		a.bucketMap[block.ID()] = bucket
	}

	a.adaptBucketPolicies()
	a.adaptPublicAccessBlocks()

	var buckets []s3.Bucket
	for _, bucket := range a.bucketMap {
		buckets = append(buckets, *bucket)
	}

	return buckets
}

func getEncryption(block *terraform.Block, a *adapter) s3.Encryption {
	if sseConfgihuration := block.GetBlock("server_side_encryption_configuration"); sseConfgihuration != nil {
		return newS3Encryption(block, sseConfgihuration)
	}
	if val, ok := applyForBucketRelatedResource(a, block, "aws_s3_bucket_server_side_encryption_configuration", func(resource *terraform.Block) s3.Encryption {
		return newS3Encryption(resource, resource)
	}); ok {
		return val
	}
	return s3.Encryption{
		Metadata:  block.GetMetadata(),
		Enabled:   defsecTypes.BoolDefault(false, block.GetMetadata()),
		KMSKeyId:  defsecTypes.StringDefault("", block.GetMetadata()),
		Algorithm: defsecTypes.StringDefault("", block.GetMetadata()),
	}
}

func newS3Encryption(root *terraform.Block, sseConfgihuration *terraform.Block) s3.Encryption {
	return s3.Encryption{
		Metadata: root.GetMetadata(),
		Enabled:  isEncrypted(sseConfgihuration),
		Algorithm: terraform.MapNestedAttribute(
			sseConfgihuration,
			"rule.apply_server_side_encryption_by_default.sse_algorithm",
			func(attr *terraform.Attribute, parent *terraform.Block) defsecTypes.StringValue {
				return attr.AsStringValueOrDefault("", parent)
			},
		),
		KMSKeyId: terraform.MapNestedAttribute(
			sseConfgihuration,
			"rule.apply_server_side_encryption_by_default.kms_master_key_id",
			func(attr *terraform.Attribute, parent *terraform.Block) defsecTypes.StringValue {
				return attr.AsStringValueOrDefault("", parent)
			},
		),
	}
}

func getVersioning(block *terraform.Block, a *adapter) s3.Versioning {
	versioning := s3.Versioning{
		Metadata:  block.GetMetadata(),
		Enabled:   defsecTypes.BoolDefault(false, block.GetMetadata()),
		MFADelete: defsecTypes.BoolDefault(false, block.GetMetadata()),
	}
	if lockBlock := block.GetBlock("object_lock_configuration"); lockBlock != nil {
		if enabled := isObjeckLockEnabled(lockBlock); enabled != nil {
			versioning.Enabled = *enabled
		}
	}
	if vBlock := block.GetBlock("versioning"); vBlock != nil {
		versioning.Enabled = vBlock.GetAttribute("enabled").AsBoolValueOrDefault(true, vBlock)
		versioning.MFADelete = vBlock.GetAttribute("mfa_delete").AsBoolValueOrDefault(false, vBlock)
	}

	if enabled, ok := applyForBucketRelatedResource(a, block, "aws_s3_bucket_object_lock_configuration", func(resource *terraform.Block) *defsecTypes.BoolValue {
		if block.GetAttribute("object_lock_enabled").IsTrue() {
			return isObjeckLockEnabled(resource)
		}
		return nil
	}); ok && enabled != nil {
		versioning.Enabled = *enabled
	}

	if val, ok := applyForBucketRelatedResource(a, block, "aws_s3_bucket_versioning", getVersioningFromResource); ok {
		return val
	}
	return versioning
}

func isObjeckLockEnabled(resource *terraform.Block) *defsecTypes.BoolValue {
	var val defsecTypes.BoolValue
	attr := resource.GetAttribute("object_lock_enabled")
	switch {
	case attr.IsNil(): // enabled by default
		val = defsecTypes.BoolDefault(true, resource.GetMetadata())
	case attr.Equals("Enabled"):
		val = defsecTypes.Bool(true, attr.GetMetadata())
	}
	return &val
}

// from aws_s3_bucket_versioning
func getVersioningFromResource(block *terraform.Block) s3.Versioning {
	versioning := s3.Versioning{
		Metadata:  block.GetMetadata(),
		Enabled:   defsecTypes.BoolDefault(false, block.GetMetadata()),
		MFADelete: defsecTypes.BoolDefault(false, block.GetMetadata()),
	}
	if config := block.GetBlock("versioning_configuration"); config != nil {
		if status := config.GetAttribute("status"); status.IsNotNil() {
			versioning.Enabled = defsecTypes.Bool(status.Equals("Enabled", terraform.IgnoreCase), status.GetMetadata())
		}
		if mfa := config.GetAttribute("mfa_delete"); mfa.IsNotNil() {
			versioning.MFADelete = defsecTypes.Bool(mfa.Equals("Enabled", terraform.IgnoreCase), mfa.GetMetadata())
		}
	}
	return versioning
}

func getLogging(block *terraform.Block, a *adapter) s3.Logging {
	if loggingBlock := block.GetBlock("logging"); loggingBlock.IsNotNil() {
		targetBucket := loggingBlock.GetAttribute("target_bucket").AsStringValueOrDefault("", loggingBlock)
		if referencedBlock, err := a.modules.GetReferencedBlock(loggingBlock.GetAttribute("target_bucket"), loggingBlock); err == nil {
			targetBucket = defsecTypes.String(referencedBlock.FullName(), loggingBlock.GetAttribute("target_bucket").GetMetadata())
		}
		return s3.Logging{
			Metadata:     loggingBlock.GetMetadata(),
			Enabled:      defsecTypes.Bool(true, loggingBlock.GetMetadata()),
			TargetBucket: targetBucket,
		}
	}

	if val, ok := applyForBucketRelatedResource(a, block, "aws_s3_bucket_logging", func(resource *terraform.Block) s3.Logging {
		targetBucket := resource.GetAttribute("target-bucket").AsStringValueOrDefault("", resource)
		if referencedBlock, err := a.modules.GetReferencedBlock(resource.GetAttribute("target_bucket"), resource); err == nil {
			targetBucket = defsecTypes.String(referencedBlock.FullName(), resource.GetAttribute("target_bucket").GetMetadata())
		}
		return s3.Logging{
			Metadata:     resource.GetMetadata(),
			Enabled:      hasLogging(resource),
			TargetBucket: targetBucket,
		}
	}); ok {
		return val
	}

	return s3.Logging{
		Metadata:     block.GetMetadata(),
		Enabled:      defsecTypes.Bool(false, block.GetMetadata()),
		TargetBucket: defsecTypes.StringDefault("", block.GetMetadata()),
	}
}

func getBucketAcl(block *terraform.Block, a *adapter) defsecTypes.StringValue {
	aclAttr := block.GetAttribute("acl")
	if aclAttr.IsString() {
		return aclAttr.AsStringValueOrDefault("private", block)
	}

	if val, ok := applyForBucketRelatedResource(a, block, "aws_s3_bucket_acl", func(resource *terraform.Block) defsecTypes.StringValue {
		return resource.GetAttribute("acl").AsStringValueOrDefault("private", resource)
	}); ok {
		return val
	}
	return defsecTypes.StringDefault("private", block.GetMetadata())
}

func isEncrypted(sseConfgihuration *terraform.Block) defsecTypes.BoolValue {
	return terraform.MapNestedAttribute(
		sseConfgihuration,
		"rule.apply_server_side_encryption_by_default.sse_algorithm",
		func(attr *terraform.Attribute, parent *terraform.Block) defsecTypes.BoolValue {
			if attr.IsNil() {
				return defsecTypes.BoolDefault(false, parent.GetMetadata())
			}
			return defsecTypes.Bool(
				true,
				attr.GetMetadata(),
			)
		},
	)
}

func hasLogging(b *terraform.Block) defsecTypes.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if targetAttr := loggingBlock.GetAttribute("target_bucket"); targetAttr.IsNotNil() && targetAttr.IsNotEmpty() {
			return defsecTypes.Bool(true, targetAttr.GetMetadata())
		}
		return defsecTypes.BoolDefault(false, loggingBlock.GetMetadata())
	}
	if targetBucket := b.GetAttribute("target_bucket"); targetBucket.IsNotNil() {
		return defsecTypes.Bool(true, targetBucket.GetMetadata())
	}
	return defsecTypes.BoolDefault(false, b.GetMetadata())
}

func getLifecycle(b *terraform.Block, a *adapter) []s3.Rules {

	var rules []s3.Rules
	for _, r := range a.modules.GetReferencingResources(b, "aws_s3_bucket_lifecycle_configuration", "bucket") {
		ruleblock := r.GetBlocks("rule")
		for _, rule := range ruleblock {
			rules = append(rules, s3.Rules{
				Metadata: rule.GetMetadata(),
				Status:   rule.GetAttribute("status").AsStringValueOrDefault("Enabled", rule),
			})
		}
	}
	return rules
}

func getWebsite(b *terraform.Block, a *adapter) (website *s3.Website) {
	for _, r := range a.modules.GetReferencingResources(b, "aws_s3_bucket_website_configuration", "bucket") {
		website = &s3.Website{
			Metadata: r.GetMetadata(),
		}
	}
	return website
}

func getObject(b *terraform.Block, a *adapter) []s3.Contents {
	var object []s3.Contents
	for _, r := range a.modules.GetReferencingResources(b, "aws_s3_object", "bucket") {
		object = append(object, s3.Contents{
			Metadata: r.GetMetadata(),
		})
	}
	return object
}

func getAccelerateStatus(b *terraform.Block, a *adapter) defsecTypes.StringValue {
	var status defsecTypes.StringValue
	for _, r := range a.modules.GetReferencingResources(b, " aws_s3_bucket_accelerate_configuration", "bucket") {
		status = r.GetAttribute("status").AsStringValueOrDefault("Enabled", r)
	}
	return status
}

func applyForBucketRelatedResource[T any](a *adapter, block *terraform.Block, resType string, fn func(resource *terraform.Block) T) (T, bool) {
	for _, resource := range a.modules.GetResourcesByType(resType) {
		bucketAttr := resource.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			if bucketAttr.IsString() {
				actualBucketName := block.GetAttribute("bucket").AsStringValueOrDefault("", block).Value()
				if bucketAttr.Equals(block.ID()) || bucketAttr.Equals(actualBucketName) {
					return fn(resource), true
				}
			}
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, resource); err == nil {
				if referencedBlock.ID() == block.ID() {
					return fn(resource), true
				}
			}
		}

	}
	var res T
	return res, false
}
