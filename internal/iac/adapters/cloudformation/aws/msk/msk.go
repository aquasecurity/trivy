package msk

import (
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/msk"
)

// Adapt adapts an MSK instance
func Adapt(cfFile parser.FileContext) msk.MSK {
	return msk.MSK{
		Clusters: getClusters(cfFile),
	}
}
