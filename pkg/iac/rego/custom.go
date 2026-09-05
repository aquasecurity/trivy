package rego

import (
	checksrego "github.com/aquasecurity/trivy-checks/pkg/rego"
)

func init() {
	checksrego.RegisterBuiltins()
}
