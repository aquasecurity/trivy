//go:generate go build -o happy.wasm -buildmode=c-shared happy.go
//go:build wasip1

package main

import (
	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	moduleVersion = 1
	moduleName    = "happy"
)

func main() {}

func init() {
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

func (HappyModule) PostScan(_ types.Results) (types.Results, error) {
	return nil, nil
}
