package cloudfront

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a CloudFront instance
func Adapt(cfFile parser.FileContext) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: getDistributions(cfFile),
	}
}
