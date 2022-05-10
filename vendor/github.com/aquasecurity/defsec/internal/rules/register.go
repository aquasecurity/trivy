package rules

import (
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
)

var registeredRules []RegisteredRule

var index int

type RegisteredRule struct {
	number    int
	rule      scan.Rule
	checkFunc scan.CheckFunc
}

func (r RegisteredRule) HasLogic() bool {
	return r.checkFunc != nil
}

func (r RegisteredRule) Evaluate(s *state.State) scan.Results {
	if r.checkFunc == nil {
		return nil
	}
	results := r.checkFunc(s)
	for i := range results {
		results[i].SetRule(r.rule)
	}
	return results
}

func Register(rule scan.Rule, f scan.CheckFunc) RegisteredRule {
	registeredRule := RegisteredRule{
		number:    index,
		rule:      rule,
		checkFunc: f,
	}
	index++

	registeredRules = append(registeredRules, registeredRule)

	return registeredRule
}

func Deregister(rule RegisteredRule) {
	for i, registered := range registeredRules {
		if registered.number == rule.number {
			registeredRules = append(registeredRules[:i], registeredRules[i+1:]...)
			return
		}
	}
}

func (r RegisteredRule) Rule() scan.Rule {
	return r.rule
}

func (r *RegisteredRule) AddLink(link string) {
	r.rule.Links = append([]string{link}, r.rule.Links...)
}

func GetRegistered() []RegisteredRule {
	return registeredRules
}
