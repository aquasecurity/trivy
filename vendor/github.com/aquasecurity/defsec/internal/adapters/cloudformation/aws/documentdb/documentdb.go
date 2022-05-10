package documentdb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result documentdb.DocumentDB) {

	result.Clusters = getClusters(cfFile)
	return result

}
