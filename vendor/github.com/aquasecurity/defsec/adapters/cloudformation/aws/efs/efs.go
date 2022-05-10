package efs

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/efs"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result efs.EFS) {

	result.FileSystems = getFileSystems(cfFile)
	return result
}
