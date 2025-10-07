package cloudfront

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

func getDistributions(ctx parser.FileContext) (distributions []cloudfront.Distribution) {

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

func getDefaultCacheBehaviour(r *parser.Resource) cloudfront.CacheBehaviour {
	defaultCache := r.GetProperty("DistributionConfig.DefaultCacheBehavior")
	if defaultCache.IsNil() {
		return cloudfront.CacheBehaviour{
			Metadata: r.Metadata(),
		}
	}
	return cloudfront.CacheBehaviour{
		Metadata:             defaultCache.Metadata(),
		ViewerProtocolPolicy: defaultCache.GetStringProperty("ViewerProtocolPolicy"),
	}
}
