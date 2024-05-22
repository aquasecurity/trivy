package api

import "github.com/aquasecurity/trivy/pkg/module/serialize"

const (
	Version = 1

	ActionInsert serialize.PostScanAction = "INSERT"
	ActionUpdate serialize.PostScanAction = "UPDATE"
	ActionDelete serialize.PostScanAction = "DELETE"
)

type Module interface {
	Version() int
	Name() string
}

type Analyzer interface {
	RequiredFiles() []string
	Analyze(filePath string) (*serialize.AnalysisResult, error)
}

type PostScanner interface {
	PostScanSpec() serialize.PostScanSpec
	PostScan(serialize.Results) (serialize.Results, error)
}
