package efs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/efs"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) efs.EFS {
	return efs.EFS{
		FileSystems: getFileSystems(cfFile),
	}
}
