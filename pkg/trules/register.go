package trules

import (
	"github.com/aquasecurity/trivy/internal/rules"
	"github.com/aquasecurity/trivy/pkg/framework"
	"github.com/aquasecurity/trivy/pkg/scan"
	ruleTypes "github.com/aquasecurity/trivy/pkg/types/rules"
)

func Register(rule scan.Rule) ruleTypes.RegisteredRule {
	return rules.Register(rule)
}

func Deregister(rule ruleTypes.RegisteredRule) {
	rules.Deregister(rule)
}

func GetRegistered(fw ...framework.Framework) []ruleTypes.RegisteredRule {
	return rules.GetFrameworkRules(fw...)
}

func GetSpecRules(spec string) []ruleTypes.RegisteredRule {
	return rules.GetSpecRules(spec)
}
