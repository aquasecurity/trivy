package accessanalyzer

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/accessanalyzer"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) accessanalyzer.AccessAnalyzer {
	return accessanalyzer.AccessAnalyzer{
		Analyzers: adaptTrails(modules),
	}
}

func adaptTrails(modules terraform.Modules) []accessanalyzer.Analyzer {
	var analyzer []accessanalyzer.Analyzer

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_accessanalyzer_analyzer") {
			analyzer = append(analyzer, adaptAnalyzers(resource))
		}
	}
	return analyzer
}

func adaptAnalyzers(resource *terraform.Block) accessanalyzer.Analyzer {
	return accessanalyzer.Analyzer{
		Metadata: resource.GetMetadata(),
		Name:     resource.GetAttribute("analyzer_name").AsStringValue(),
		ARN:      resource.GetAttribute("arn").AsStringValue(),
		Active:   types.BoolDefault(false, resource.GetMetadata()),
	}
}
