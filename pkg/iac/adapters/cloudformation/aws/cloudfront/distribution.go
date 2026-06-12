package cloudfront

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getDistributions(ctx parser.FileContext) (distributions []cloudfront.Distribution) {

	distributionResources := ctx.GetResourcesByType("AWS::CloudFront::Distribution")
	deliverySources := ctx.GetResourcesByType("AWS::Logs::DeliverySource")
	deliveries := ctx.GetResourcesByType("AWS::Logs::Delivery")

	for _, r := range distributionResources {
		distribution := cloudfront.Distribution{
			Metadata: r.Metadata(),
			WAFID:    r.GetStringProperty("DistributionConfig.WebACLId"),
			Logging: cloudfront.Logging{
				Metadata: r.Metadata(),
				Bucket:   r.GetStringProperty("DistributionConfig.Logging.Bucket"),
				V2: cloudfront.LoggingV2{
					Metadata: r.Metadata(),
					Enabled:  hasV2Logging(r, deliverySources, deliveries),
				},
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

func hasV2Logging(distribution *parser.Resource, deliverySources []*parser.Resource, deliveries []*parser.Resource) iacTypes.BoolValue {

	for _, source := range deliverySources {
		logType := source.GetStringProperty("LogType")
		if logType.Value() != "ACCESS_LOGS" {
			continue
		}
		resourceArn := source.GetStringProperty("ResourceArn")
		if !strings.Contains(resourceArn.Value(), distribution.ID()) {
			continue
		}
		sourceName := source.GetStringProperty("Name")

		for _, delivery := range deliveries {
			deliverySourceName := delivery.GetStringProperty("DeliverySourceName")
			if deliverySourceName.Value() == sourceName.Value() || deliverySourceName.Value() == source.ID() {
				return iacTypes.Bool(true, distribution.Metadata())
			}
		}

	}
	return iacTypes.Bool(false, distribution.Metadata())
}
