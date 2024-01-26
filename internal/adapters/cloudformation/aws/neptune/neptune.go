package neptune

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a Neptune instance
func Adapt(cfFile parser.FileContext) neptune.Neptune {
	return neptune.Neptune{
		Clusters: getClusters(cfFile),
	}
}
