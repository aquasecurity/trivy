package s3

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
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
				Metadata: r.Metadata(),
				Enabled:  hasVersioning(r),
			},
			Logging: s3.Logging{
				Metadata: r.Metadata(),
				Enabled:  hasLogging(r),
			},
			ACL: convertAclValue(r.GetStringProperty("AccessControl", "private")),
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

func convertAclValue(aclValue types.StringValue) types.StringValue {
	matches := aclConvertRegex.FindAllString(aclValue.Value(), -1)

	return types.String(strings.ToLower(strings.Join(matches, "-")), aclValue.GetMetadata())
}

func hasLogging(r *parser.Resource) types.BoolValue {

	loggingProps := r.GetProperty("LoggingConfiguration.DestinationBucketName")

	if loggingProps.IsNil() || loggingProps.IsEmpty() {

		return types.BoolDefault(false, r.Metadata())
	}

	return types.Bool(true, loggingProps.Metadata())
}

func hasVersioning(r *parser.Resource) types.BoolValue {
	versioningProp := r.GetProperty("VersioningConfiguration.Status")

	if versioningProp.IsNil() {
		return types.BoolDefault(false, r.Metadata())
	}

	versioningEnabled := false
	if versioningProp.EqualTo("Enabled") {
		versioningEnabled = true

	}
	return types.Bool(versioningEnabled, versioningProp.Metadata())
}

func getEncryption(r *parser.Resource, _ parser.FileContext) s3.Encryption {

	encryption := s3.Encryption{
		Metadata:  r.Metadata(),
		Enabled:   types.BoolDefault(false, r.Metadata()),
		Algorithm: types.StringDefault("", r.Metadata()),
		KMSKeyId:  types.StringDefault("", r.Metadata()),
	}

	if encryptProps := r.GetProperty("BucketEncryption.ServerSideEncryptionConfiguration"); encryptProps.IsNotNil() {
		for _, rule := range encryptProps.AsList() {
			if algo := rule.GetProperty("ServerSideEncryptionByDefault.SSEAlgorithm"); algo.EqualTo("AES256") {
				encryption.Enabled = types.Bool(true, algo.Metadata())
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
