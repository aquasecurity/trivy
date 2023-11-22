package rules

import (
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/trivy/internal/rules"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Register(rule scan.Rule) types.RegisteredRule {
	return rules.Register(rule)
}

func Deregister(rule types.RegisteredRule) {
	rules.Deregister(rule)
}

func GetRegistered(fw ...framework.Framework) []types.RegisteredRule {
	return rules.GetFrameworkRules(fw...)
}

func GetSpecRules(spec string) []types.RegisteredRule {
	return rules.GetSpecRules(spec)
}
