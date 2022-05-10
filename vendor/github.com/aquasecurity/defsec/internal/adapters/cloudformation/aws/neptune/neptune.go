package neptune

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result neptune.Neptune) {

	result.Clusters = getClusters(cfFile)
	return result
}
