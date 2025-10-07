package cloudfront

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: adaptDistributions(modules),
	}
}

func adaptDistributions(modules terraform.Modules) []cloudfront.Distribution {
	var distributions []cloudfront.Distribution
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudfront_distribution") {
			distributions = append(distributions, adaptDistribution(resource))
		}
	}
	return distributions
}

func adaptDistribution(resource *terraform.Block) cloudfront.Distribution {

	distribution := cloudfront.Distribution{
		Metadata: resource.GetMetadata(),
		WAFID:    types.StringDefault("", resource.GetMetadata()),
		Logging: cloudfront.Logging{
			Metadata: resource.GetMetadata(),
			Bucket:   types.StringDefault("", resource.GetMetadata()),
		},
		DefaultCacheBehaviour: cloudfront.CacheBehaviour{
			Metadata:             resource.GetMetadata(),
			ViewerProtocolPolicy: types.StringDefault("", resource.GetMetadata()),
		},
		OrdererCacheBehaviours: nil,
		ViewerCertificate: cloudfront.ViewerCertificate{
			Metadata:               resource.GetMetadata(),
			MinimumProtocolVersion: types.StringDefault("TLSv1", resource.GetMetadata()),
		},
	}

	distribution.WAFID = resource.GetAttribute("web_acl_id").AsStringValueOrDefault("", resource)

	if loggingBlock := resource.GetBlock("logging_config"); loggingBlock.IsNotNil() {
		distribution.Logging.Metadata = loggingBlock.GetMetadata()
		bucketAttr := loggingBlock.GetAttribute("bucket")
		distribution.Logging.Bucket = bucketAttr.AsStringValueOrDefault("", loggingBlock)
	}

	if defaultCacheBlock := resource.GetBlock("default_cache_behavior"); defaultCacheBlock.IsNotNil() {
		distribution.DefaultCacheBehaviour.Metadata = defaultCacheBlock.GetMetadata()
		viewerProtocolPolicyAttr := defaultCacheBlock.GetAttribute("viewer_protocol_policy")
		distribution.DefaultCacheBehaviour.ViewerProtocolPolicy = viewerProtocolPolicyAttr.AsStringValueOrDefault("", defaultCacheBlock)
	}

	orderedCacheBlocks := resource.GetBlocks("ordered_cache_behavior")
	for _, orderedCacheBlock := range orderedCacheBlocks {
		viewerProtocolPolicyAttr := orderedCacheBlock.GetAttribute("viewer_protocol_policy")
		viewerProtocolPolicyVal := viewerProtocolPolicyAttr.AsStringValueOrDefault("", orderedCacheBlock)
		distribution.OrdererCacheBehaviours = append(distribution.OrdererCacheBehaviours, cloudfront.CacheBehaviour{
			Metadata:             orderedCacheBlock.GetMetadata(),
			ViewerProtocolPolicy: viewerProtocolPolicyVal,
		})
	}

	if viewerCertBlock := resource.GetBlock("viewer_certificate"); viewerCertBlock.IsNotNil() {
		distribution.ViewerCertificate = cloudfront.ViewerCertificate{
			Metadata:                     viewerCertBlock.GetMetadata(),
			MinimumProtocolVersion:       viewerCertBlock.GetAttribute("minimum_protocol_version").AsStringValueOrDefault("TLSv1", viewerCertBlock),
			SSLSupportMethod:             viewerCertBlock.GetAttribute("ssl_support_method").AsStringValueOrDefault("", viewerCertBlock),
			CloudfrontDefaultCertificate: viewerCertBlock.GetAttribute("cloudfront_default_certificate").AsBoolValueOrDefault(false, viewerCertBlock),
		}
	}

	return distribution
}
