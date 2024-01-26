package msk

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an MSK instance
func Adapt(cfFile parser.FileContext) msk.MSK {
	return msk.MSK{
		Clusters: getClusters(cfFile),
	}
}
