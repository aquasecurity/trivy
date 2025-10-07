package neptune

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/aws/neptune"
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
)

// Adapt adapts a Neptune instance
func Adapt(cfFile parser.FileContext) neptune.Neptune {
	return neptune.Neptune{
		Clusters: getClusters(cfFile),
	}
}
