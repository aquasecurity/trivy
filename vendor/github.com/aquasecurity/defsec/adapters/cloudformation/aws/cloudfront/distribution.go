package cloudfront

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/cloudfront"
)

func getDistributions(ctx parser.FileContext) (distributions []cloudfront.Distribution) {

	distributionResources := ctx.GetResourcesByType("AWS::CloudFront::Distribution")

	for _, r := range distributionResources {
		distribution := cloudfront.Distribution{
			Metadata: r.Metadata(),
			WAFID:    r.GetStringProperty("DistributionConfig.WebACLId"),
			Logging: cloudfront.Logging{
				Bucket: r.GetStringProperty("DistributionConfig.Logging.Bucket"),
			},
			DefaultCacheBehaviour:  getDefaultCacheBehaviour(r),
			OrdererCacheBehaviours: nil,
			ViewerCertificate: cloudfront.ViewerCertificate{
				MinimumProtocolVersion: r.GetStringProperty("DistributionConfig.ViewerCertificate.MinimumProtocolVersion"),
			},
		}

		distributions = append(distributions, distribution)
	}

	return distributions
}

func getDefaultCacheBehaviour(r *parser.Resource) cloudfront.CacheBehaviour {
	defaultCache := r.GetProperty("DistributionConfig.DefaultCacheBehavior")
	if defaultCache.IsNil() {
		return cloudfront.CacheBehaviour{
			Metadata:             r.Metadata(),
			ViewerProtocolPolicy: types.StringDefault("allow-all", r.Metadata()),
		}
	}
	protoProp := r.GetProperty("DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy")
	if protoProp.IsNotString() {
		return cloudfront.CacheBehaviour{
			Metadata:             r.Metadata(),
			ViewerProtocolPolicy: types.StringDefault("allow-all", r.Metadata()),
		}
	}

	return cloudfront.CacheBehaviour{
		Metadata:             r.Metadata(),
		ViewerProtocolPolicy: protoProp.AsStringValue(),
	}
}
