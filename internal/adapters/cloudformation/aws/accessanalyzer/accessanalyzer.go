package accessanalyzer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/accessanalyzer"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an AccessAnalyzer instance
func Adapt(cfFile parser.FileContext) accessanalyzer.AccessAnalyzer {
	return accessanalyzer.AccessAnalyzer{
		Analyzers: getAccessAnalyzer(cfFile),
	}
}
