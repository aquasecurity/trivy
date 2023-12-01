package documentdb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) documentdb.DocumentDB {
	return documentdb.DocumentDB{
		Clusters: getClusters(cfFile),
	}
}
