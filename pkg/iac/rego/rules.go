package rego

import (
	trules "github.com/aquasecurity/trivy-checks/pkg/rules"
)

func init() {
	LoadAndRegister()
	for _, r := range trules.GetRules() {
		Register(r)
	}
}
