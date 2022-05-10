package dynamodb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result dynamodb.DynamoDB) {

	result.DAXClusters = getClusters(cfFile)
	return result

}
