package eks

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/eks"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result eks.EKS) {

	result.Clusters = getClusters(cfFile)
	return result
}
