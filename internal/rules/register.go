package rules

import (
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scan"
	dftypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy-policies/rules/specs"

	"github.com/aquasecurity/trivy/pkg/types"
)

type registry struct {
	sync.RWMutex
	index      int
	frameworks map[framework.Framework][]types.RegisteredRule
}

var coreRegistry = registry{
	frameworks: make(map[framework.Framework][]types.RegisteredRule),
}

func Reset() {
	coreRegistry.Reset()
}

func Register(rule scan.Rule) types.RegisteredRule {
	return coreRegistry.register(rule)
}

func Deregister(rule types.RegisteredRule) {
	coreRegistry.deregister(rule)
}

func (r *registry) register(rule scan.Rule) types.RegisteredRule {
	r.Lock()
	defer r.Unlock()
	if len(rule.Frameworks) == 0 {
		rule.Frameworks = map[framework.Framework][]string{framework.Default: nil}
	}
	registeredRule := types.RegisteredRule{
		Number: r.index,
		Rule:   rule,
	}
	r.index++
	for fw := range rule.Frameworks {
		r.frameworks[fw] = append(r.frameworks[fw], registeredRule)
	}

	r.frameworks[framework.ALL] = append(r.frameworks[framework.ALL], registeredRule)

	return registeredRule
}

func (r *registry) deregister(rule types.RegisteredRule) {
	r.Lock()
	defer r.Unlock()
	for fw := range r.frameworks {
		for i, registered := range r.frameworks[fw] {
			if registered.Number == rule.Number {
				r.frameworks[fw] = append(r.frameworks[fw][:i], r.frameworks[fw][i+1:]...)
				break
			}
		}
	}
}

func (r *registry) getFrameworkRules(fw ...framework.Framework) []types.RegisteredRule {
	r.RLock()
	defer r.RUnlock()
	var registered []types.RegisteredRule
	if len(fw) == 0 {
		fw = []framework.Framework{framework.Default}
	}
	unique := make(map[int]struct{})
	for _, f := range fw {
		for _, rule := range r.frameworks[f] {
			if _, ok := unique[rule.Number]; ok {
				continue
			}
			registered = append(registered, rule)
			unique[rule.Number] = struct{}{}
		}
	}
	return registered
}

func (r *registry) getSpecRules(spec string) []types.RegisteredRule {
	r.RLock()
	defer r.RUnlock()
	var specRules []types.RegisteredRule

	var complianceSpec dftypes.ComplianceSpec
	specContent := specs.GetSpec(spec)
	if err := yaml.Unmarshal([]byte(specContent), &complianceSpec); err != nil {
		return nil
	}

	registered := r.getFrameworkRules(framework.ALL)
	for _, rule := range registered {
		for _, csRule := range complianceSpec.Spec.Controls {
			if len(csRule.Checks) > 0 {
				for _, c := range csRule.Checks {
					if rule.GetRule().AVDID == c.ID {
						specRules = append(specRules, rule)
					}
				}
			}
		}
	}

	return specRules
}

func (r *registry) Reset() {
	r.Lock()
	defer r.Unlock()
	r.frameworks = make(map[framework.Framework][]types.RegisteredRule)
}

func GetFrameworkRules(fw ...framework.Framework) []types.RegisteredRule {
	return coreRegistry.getFrameworkRules(fw...)
}

func GetSpecRules(spec string) []types.RegisteredRule {
	if len(spec) > 0 {
		return coreRegistry.getSpecRules(spec)
	}

	return GetFrameworkRules()
}
