package s3

import (
	"regexp"
	"strings"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

var aclConvertRegex = regexp.MustCompile(`[A-Z][^A-Z]*`)

func getBuckets(cfFile parser.FileContext) []s3.Bucket {
	var buckets []s3.Bucket
	bucketResources := cfFile.GetResourcesByType("AWS::S3::Bucket")

	for _, r := range bucketResources {
		s3b := s3.Bucket{
			Metadata:          r.Metadata(),
			Name:              r.GetStringProperty("BucketName"),
			PublicAccessBlock: getPublicAccessBlock(r),
			Encryption:        getEncryption(r, cfFile),
			Versioning: s3.Versioning{
				Metadata:  r.Metadata(),
				Enabled:   hasVersioning(r),
				MFADelete: defsecTypes.BoolUnresolvable(r.Metadata()),
			},
			Logging:                       getLogging(r),
			ACL:                           convertAclValue(r.GetStringProperty("AccessControl", "private")),
			LifecycleConfiguration:        getLifecycle(r),
			AccelerateConfigurationStatus: r.GetStringProperty("AccelerateConfiguration.AccelerationStatus"),
			Website:                       getWebsite(r),
			BucketLocation:                defsecTypes.String("", r.Metadata()),
			Objects:                       nil,
		}

		buckets = append(buckets, s3b)
	}
	return buckets
}

func getPublicAccessBlock(r *parser.Resource) *s3.PublicAccessBlock {
	if block := r.GetProperty("PublicAccessBlockConfiguration"); block.IsNil() {
		return nil
	}

	return &s3.PublicAccessBlock{
		Metadata:              r.Metadata(),
		BlockPublicACLs:       r.GetBoolProperty("PublicAccessBlockConfiguration.BlockPublicAcls"),
		BlockPublicPolicy:     r.GetBoolProperty("PublicAccessBlockConfiguration.BlockPublicPolicy"),
		IgnorePublicACLs:      r.GetBoolProperty("PublicAccessBlockConfiguration.IgnorePublicAcls"),
		RestrictPublicBuckets: r.GetBoolProperty("PublicAccessBlockConfiguration.RestrictPublicBuckets"),
	}
}

func convertAclValue(aclValue defsecTypes.StringValue) defsecTypes.StringValue {
	matches := aclConvertRegex.FindAllString(aclValue.Value(), -1)

	return defsecTypes.String(strings.ToLower(strings.Join(matches, "-")), aclValue.GetMetadata())
}

func getLogging(r *parser.Resource) s3.Logging {

	logging := s3.Logging{
		Metadata:     r.Metadata(),
		Enabled:      defsecTypes.BoolDefault(false, r.Metadata()),
		TargetBucket: defsecTypes.StringDefault("", r.Metadata()),
	}

	if config := r.GetProperty("LoggingConfiguration"); config.IsNotNil() {
		logging.TargetBucket = config.GetStringProperty("DestinationBucketName")
		if logging.TargetBucket.IsNotEmpty() || !logging.TargetBucket.GetMetadata().IsResolvable() {
			logging.Enabled = defsecTypes.Bool(true, config.Metadata())
		}
	}
	return logging
}

func hasVersioning(r *parser.Resource) defsecTypes.BoolValue {
	versioningProp := r.GetProperty("VersioningConfiguration.Status")

	if versioningProp.IsNil() {
		return defsecTypes.BoolDefault(false, r.Metadata())
	}

	versioningEnabled := false
	if versioningProp.EqualTo("Enabled") {
		versioningEnabled = true

	}
	return defsecTypes.Bool(versioningEnabled, versioningProp.Metadata())
}

func getEncryption(r *parser.Resource, _ parser.FileContext) s3.Encryption {

	encryption := s3.Encryption{
		Metadata:  r.Metadata(),
		Enabled:   defsecTypes.BoolDefault(false, r.Metadata()),
		Algorithm: defsecTypes.StringDefault("", r.Metadata()),
		KMSKeyId:  defsecTypes.StringDefault("", r.Metadata()),
	}

	if encryptProps := r.GetProperty("BucketEncryption.ServerSideEncryptionConfiguration"); encryptProps.IsNotNil() {
		for _, rule := range encryptProps.AsList() {
			if algo := rule.GetProperty("ServerSideEncryptionByDefault.SSEAlgorithm"); algo.EqualTo("AES256") {
				encryption.Enabled = defsecTypes.Bool(true, algo.Metadata())
			} else if kmsKeyProp := rule.GetProperty("ServerSideEncryptionByDefault.KMSMasterKeyID"); !kmsKeyProp.IsEmpty() && kmsKeyProp.IsString() {
				encryption.KMSKeyId = kmsKeyProp.AsStringValue()
			}
			if encryption.Enabled.IsFalse() {
				encryption.Enabled = rule.GetBoolProperty("BucketKeyEnabled", false)
			}
		}
	}

	return encryption
}

func getLifecycle(resource *parser.Resource) []s3.Rules {
	LifecycleProp := resource.GetProperty("LifecycleConfiguration")
	RuleProp := LifecycleProp.GetProperty("Rules")

	var rule []s3.Rules

	if RuleProp.IsNil() || RuleProp.IsNotList() {
		return rule
	}

	for _, r := range RuleProp.AsList() {
		rule = append(rule, s3.Rules{
			Metadata: r.Metadata(),
			Status:   r.GetStringProperty("Status"),
		})
	}
	return rule
}

func getWebsite(r *parser.Resource) *s3.Website {
	if block := r.GetProperty("WebsiteConfiguration"); block.IsNil() {
		return nil
	} else {
		return &s3.Website{
			Metadata: block.Metadata(),
		}
	}
}
