package cloudfront

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getDistributions(ctx parser2.FileContext) (distributions []cloudfront.Distribution) {

	distributionResources := ctx.GetResourcesByType("AWS::CloudFront::Distribution")

	for _, r := range distributionResources {
		distribution := cloudfront.Distribution{
			Metadata: r.Metadata(),
			WAFID:    r.GetStringProperty("DistributionConfig.WebACLId"),
			Logging: cloudfront.Logging{
				Metadata: r.Metadata(),
				Bucket:   r.GetStringProperty("DistributionConfig.Logging.Bucket"),
			},
			DefaultCacheBehaviour:  getDefaultCacheBehaviour(r),
			OrdererCacheBehaviours: nil,
			ViewerCertificate: cloudfront.ViewerCertificate{
				Metadata:               r.Metadata(),
				MinimumProtocolVersion: r.GetStringProperty("DistributionConfig.ViewerCertificate.MinimumProtocolVersion"),
			},
		}

		distributions = append(distributions, distribution)
	}

	return distributions
}

func getDefaultCacheBehaviour(r *parser2.Resource) cloudfront.CacheBehaviour {
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
