package redshift

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/redshift"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result redshift.Redshift) {

	result.Clusters = getClusters(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	return result

}
