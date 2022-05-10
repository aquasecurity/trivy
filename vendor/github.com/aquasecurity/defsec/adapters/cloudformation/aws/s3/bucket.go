package s3

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/s3"
)

var aclConvertRegex = regexp.MustCompile(`[A-Z][^A-Z]*`)

func getBuckets(cfFile parser.FileContext) []s3.Bucket {
	var buckets []s3.Bucket
	bucketResources := cfFile.GetResourceByType("AWS::S3::Bucket")

	for _, r := range bucketResources {
		s3b := s3.Bucket{
			Metadata:   r.Metadata(),
			Name:       r.GetStringProperty("BucketName"),
			Encryption: getEncryption(r, cfFile),
			ACL:        convertAclValue(r.GetStringProperty("AccessControl", "private")),
			Logging: s3.Logging{
				Metadata: r.Metadata(),
				Enabled:  hasLogging(r),
			},
			Versioning: s3.Versioning{
				Metadata: r.Metadata(),
				Enabled:  hasVersioning(r),
			},
			PublicAccessBlock: getPublicAccessBlock(r),
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

	encryptProps := r.GetProperty("BucketEncryption.ServerSideEncryptionConfiguration")

	if encryptProps.IsNil() {
		return s3.Encryption{
			Metadata:  r.Metadata(),
			Enabled:   types.BoolDefault(false, r.Metadata()),
			Algorithm: types.StringDefault("", r.Metadata()),
			KMSKeyId:  types.StringDefault("", r.Metadata()),
		}
	}

	enc := s3.Encryption{
		Metadata:  r.Metadata(),
		Algorithm: types.StringDefault("", r.Metadata()),
		KMSKeyId:  types.StringDefault("", r.Metadata()),
	}

	list := encryptProps.AsList()
	if len(list) == 0 {
		enc.Enabled = types.BoolDefault(false, r.Metadata())
		return enc
	}

	enc.Enabled = list[0].GetBoolProperty("BucketKeyEnabled")
	return enc

}
