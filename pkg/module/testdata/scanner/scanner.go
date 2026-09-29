//go:generate go build -o scanner.wasm -buildmode=c-shared scanner.go
//go:build wasip1

package main

import (
	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	moduleVersion = 2
	moduleName    = "scanner"
)

func main() {}

func init() {
	wasm.RegisterModule(PostScannerModule{})
}

type PostScannerModule struct{}

func (PostScannerModule) Version() int {
	return moduleVersion
}

func (PostScannerModule) Name() string {
	return moduleName
}

func (PostScannerModule) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionInsert, // Add new vulnerabilities
	}
}

func (PostScannerModule) PostScan(_ types.Results) (types.Results, error) {
	return nil, nil
}
