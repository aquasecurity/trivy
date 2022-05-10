package rules

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/scan"
)

func Register(rule scan.Rule, f scan.CheckFunc) rules.RegisteredRule {
	return rules.Register(rule, f)
}

func GetRegistered() (registered []rules.RegisteredRule) {
	return rules.GetRegistered()
}
