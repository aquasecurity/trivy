package accessanalyzer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/accessanalyzer"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) accessanalyzer.AccessAnalyzer {
	return accessanalyzer.AccessAnalyzer{
		Analyzers: getAccessAnalyzer(cfFile),
	}
}
