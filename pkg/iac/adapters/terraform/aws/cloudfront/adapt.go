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
			distribution := adaptDistribution(resource)

			distribution.Logging.V2 = cloudfront.LoggingV2{
				Metadata: resource.GetMetadata(),
				Enabled:  hasV2Logging(modules, resource),
			}

			distributions = append(distributions, distribution)
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

func hasV2Logging(modules terraform.Modules, distributionBlock *terraform.Block) types.BoolValue {
	metadata := distributionBlock.GetMetadata()

	sources := modules.GetReferencingResources(distributionBlock, "aws_cloudwatch_log_delivery_source", "resource_arn")
	for _, source := range sources {
		if !source.GetAttribute("log_type").Equals("ACCESS_LOGS") {
			continue
		}

		deliveries := modules.GetReferencingResources(source, "aws_cloudwatch_log_delivery", "delivery_source_name")
		if len(deliveries) > 0 {
			return types.Bool(true, metadata)
		}
	}

	return types.Bool(false, metadata)

}
