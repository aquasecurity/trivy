package accessanalyzer

import "github.com/aquasecurity/trivy/pkg/types"

type AccessAnalyzer struct {
	Analyzers []Analyzer
}

type Analyzer struct {
	Metadata types.MisconfigMetadata
	ARN      types.StringValue
	Name     types.StringValue
	Active   types.BoolValue
	Findings []Findings
}

type Findings struct {
	Metadata types.MisconfigMetadata
}
