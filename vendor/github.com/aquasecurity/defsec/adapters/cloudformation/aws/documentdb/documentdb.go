package documentdb

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/documentdb"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result documentdb.DocumentDB) {

	result.Clusters = getClusters(cfFile)
	return result

}
