package redshift

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a RedShift instance
func Adapt(cfFile parser.FileContext) redshift.Redshift {
	return redshift.Redshift{
		Clusters:          getClusters(cfFile),
		SecurityGroups:    getSecurityGroups(cfFile),
		ClusterParameters: getParameters(cfFile),
		ReservedNodes:     nil,
	}
}
