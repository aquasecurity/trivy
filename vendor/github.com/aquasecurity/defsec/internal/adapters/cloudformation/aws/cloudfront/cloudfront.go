package cloudfront

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudfront.Cloudfront) {

	result.Distributions = getDistributions(cfFile)
	return result

}
