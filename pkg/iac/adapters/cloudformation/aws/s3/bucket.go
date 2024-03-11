package s3

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
				MFADelete: iacTypes.BoolUnresolvable(r.Metadata()),
			},
			Logging:                       getLogging(r),
			ACL:                           convertAclValue(r.GetStringProperty("AccessControl", "private")),
			LifecycleConfiguration:        getLifecycle(r),
			AccelerateConfigurationStatus: r.GetStringProperty("AccelerateConfiguration.AccelerationStatus"),
			Website:                       getWebsite(r),
			BucketLocation:                iacTypes.String("", r.Metadata()),
			Objects:                       nil,
		}

		buckets = append(buckets, s3b)
	}

	slices.SortFunc(buckets, func(a, b s3.Bucket) int {
		return cmp.Compare(a.Name.Value(), b.Name.Value())
	})

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

func convertAclValue(aclValue iacTypes.StringValue) iacTypes.StringValue {
	matches := aclConvertRegex.FindAllString(aclValue.Value(), -1)

	return iacTypes.String(strings.ToLower(strings.Join(matches, "-")), aclValue.GetMetadata())
}

func getLogging(r *parser.Resource) s3.Logging {
	logging := s3.Logging{
		Metadata:     r.Metadata(),
		Enabled:      iacTypes.BoolDefault(false, r.Metadata()),
		TargetBucket: iacTypes.StringDefault("", r.Metadata()),
	}

	if config := r.GetProperty("LoggingConfiguration"); config.IsNotNil() {
		logging.TargetBucket = config.GetStringProperty("DestinationBucketName")
		if logging.TargetBucket.IsNotEmpty() || !logging.TargetBucket.GetMetadata().IsResolvable() {
			logging.Enabled = iacTypes.Bool(true, config.Metadata())
		}
	}
	return logging
}

func hasVersioning(r *parser.Resource) iacTypes.BoolValue {
	versioningProp := r.GetProperty("VersioningConfiguration.Status")

	if versioningProp.IsNil() {
		return iacTypes.BoolDefault(false, r.Metadata())
	}

	versioningEnabled := false
	if versioningProp.EqualTo("Enabled") {
		versioningEnabled = true

	}
	return iacTypes.Bool(versioningEnabled, versioningProp.Metadata())
}

func getEncryption(r *parser.Resource, _ parser.FileContext) s3.Encryption {
	encryption := s3.Encryption{
		Metadata:  r.Metadata(),
		Enabled:   iacTypes.BoolDefault(false, r.Metadata()),
		Algorithm: iacTypes.StringDefault("", r.Metadata()),
		KMSKeyId:  iacTypes.StringDefault("", r.Metadata()),
	}

	if encryptProps := r.GetProperty("BucketEncryption.ServerSideEncryptionConfiguration"); encryptProps.IsNotNil() {
		for _, rule := range encryptProps.AsList() {
			algo := rule.GetProperty("ServerSideEncryptionByDefault.SSEAlgorithm")
			if algo.IsString() {
				algoVal := algo.AsString()
				isValidAlgo := slices.Contains(s3types.ServerSideEncryption("").Values(), s3types.ServerSideEncryption(algoVal))
				encryption.Enabled = iacTypes.Bool(isValidAlgo, algo.Metadata())
				encryption.Algorithm = algo.AsStringValue()
			}

			kmsKeyProp := rule.GetProperty("ServerSideEncryptionByDefault.KMSMasterKeyID")
			if !kmsKeyProp.IsEmpty() && kmsKeyProp.IsString() {
				encryption.KMSKeyId = kmsKeyProp.AsStringValue()
			}
		}
	}

	return encryption
}

func getLifecycle(resource *parser.Resource) []s3.Rules {
	RuleProp := resource.GetProperty("LifecycleConfiguration.Rules")

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
