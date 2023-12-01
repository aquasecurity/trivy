package eks

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) eks.EKS {
	return eks.EKS{
		Clusters: getClusters(cfFile),
	}
}
