package dynamodb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{
		DAXClusters: getClusters(cfFile),
	}
}
