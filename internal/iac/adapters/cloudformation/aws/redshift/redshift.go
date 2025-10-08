package redshift

import (
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/redshift"
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
