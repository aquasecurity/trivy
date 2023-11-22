package accessanalyzer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/accessanalyzer"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

func getAccessAnalyzer(ctx parser.FileContext) (analyzers []accessanalyzer.Analyzer) {

	analyzersList := ctx.GetResourcesByType("AWS::AccessAnalyzer::Analyzer")

	for _, r := range analyzersList {
		aa := accessanalyzer.Analyzer{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("AnalyzerName"),
			ARN:      r.StringDefault(""),
			Active:   types.BoolDefault(false, r.Metadata()),
		}

		analyzers = append(analyzers, aa)
	}
	return analyzers
}
