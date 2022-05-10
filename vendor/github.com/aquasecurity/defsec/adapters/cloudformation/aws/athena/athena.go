package athena

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/athena"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result athena.Athena) {
	result.Workgroups = getWorkGroups(cfFile)
	return result
}
