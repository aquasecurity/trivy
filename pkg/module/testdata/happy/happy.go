//go:generate tinygo build -o happy.wasm -scheduler=none -target=wasi --no-debug happy.go
//go:build tinygo.wasm

package main

import (
	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
)

const (
	moduleVersion = 1
	moduleName    = "happy"
)

func main() {
	wasm.RegisterModule(HappyModule{})
}

type HappyModule struct{}

func (HappyModule) Version() int {
	return moduleVersion
}

func (HappyModule) Name() string {
	return moduleName
}

func (HappyModule) RequiredFiles() []string {
	return []string{}
}

func (s HappyModule) Analyze(_ string) (*serialize.AnalysisResult, error) {
	return nil, nil
}

func (HappyModule) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionInsert, // Add new vulnerabilities
	}
}

func (HappyModule) PostScan(_ serialize.Results) (serialize.Results, error) {
	return nil, nil
}
