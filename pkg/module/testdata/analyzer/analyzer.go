//go:generate tinygo build -o analyzer.wasm -scheduler=none -target=wasi --no-debug analyzer.go
//go:build tinygo.wasm

package main

import (
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
)

const (
	moduleVersion = 1
	moduleName    = "analyzer"
)

func main() {
	wasm.RegisterModule(AnalyzerModule{})
}

type AnalyzerModule struct{}

func (AnalyzerModule) Version() int {
	return moduleVersion
}

func (AnalyzerModule) Name() string {
	return moduleName
}

func (AnalyzerModule) RequiredFiles() []string {
	return []string{
		`foo(.?)`,
	}
}

func (s AnalyzerModule) Analyze(_ string) (*serialize.AnalysisResult, error) {
	return nil, nil
}
