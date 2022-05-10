package msk

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result msk.MSK) {

	result.Clusters = getClusters(cfFile)
	return result

}
