package eks

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an EKS instance
func Adapt(cfFile parser.FileContext) eks.EKS {
	return eks.EKS{
		Clusters: getClusters(cfFile),
	}
}
