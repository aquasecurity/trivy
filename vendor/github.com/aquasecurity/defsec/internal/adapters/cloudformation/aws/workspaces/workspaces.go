package workspaces

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/workspaces"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result workspaces.WorkSpaces) {

	result.WorkSpaces = getWorkSpaces(cfFile)
	return result
}
