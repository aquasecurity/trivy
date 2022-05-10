package rules

import (
	"github.com/aquasecurity/defsec/state"
)

type CheckFunc func(s *state.State) (results Results)

var registeredRules []RegisteredRule

type RegisteredRule struct {
	rule      Rule
	checkFunc CheckFunc
}

func (r RegisteredRule) HasLogic() bool {
	return r.checkFunc != nil
}

func (r RegisteredRule) Evaluate(s *state.State) Results {
	if r.checkFunc == nil {
		return nil
	}
	results := r.checkFunc(s)
	for i := range results {
		results[i].rule = r.rule
	}
	return results
}

func Register(rule Rule, f CheckFunc) RegisteredRule {
	registeredRule := RegisteredRule{
		rule:      rule,
		checkFunc: f,
	}

	registeredRules = append(registeredRules, registeredRule)

	return registeredRule
}

func (r RegisteredRule) Rule() Rule {
	return r.rule
}

func (r *RegisteredRule) AddLink(link string) {
	r.rule.Links = append([]string{link}, r.rule.Links...)
}

func GetRegistered() []RegisteredRule {
	return registeredRules
}
