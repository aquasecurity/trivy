package neptune

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) neptune.Neptune {
	return neptune.Neptune{
		Clusters: getClusters(cfFile),
	}
}
