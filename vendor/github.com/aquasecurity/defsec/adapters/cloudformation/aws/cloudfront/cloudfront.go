package cloudfront

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/cloudfront"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudfront.Cloudfront) {

	result.Distributions = getDistributions(cfFile)
	return result

}
