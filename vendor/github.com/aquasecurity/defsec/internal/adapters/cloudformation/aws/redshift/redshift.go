package redshift

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result redshift.Redshift) {

	result.Clusters = getClusters(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	return result

}
