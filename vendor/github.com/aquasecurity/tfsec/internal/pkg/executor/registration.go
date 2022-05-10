package executor

import (
	"fmt"
	"sort"
	"sync"

	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/legacy"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

var rulesLock sync.Mutex
var registeredRules []rule.Rule

// RegisterCheckRule registers a new Rule which should be run on future scans
func RegisterCheckRule(rule rule.Rule) {
	rulesLock.Lock()
	defer rulesLock.Unlock()
	registeredRules = append(registeredRules, rule)
}

func DeregisterCheckRule(r rule.Rule) {
	rulesLock.Lock()
	defer rulesLock.Unlock()
	var filtered []rule.Rule
	for _, existing := range registeredRules {
		if existing.ID() != r.ID() {
			filtered = append(filtered, existing)
		}
	}
	registeredRules = filtered
}

// GetRegisteredRules provides all Checks which have been registered with this package
func GetRegisteredRules() []rule.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID() < registeredRules[j].ID()
	})

	combined := make([]rule.Rule, len(registeredRules))
	copy(combined, registeredRules)
	for _, defsecRule := range rules.GetRegistered() {
		if defsecRule.Rule().Terraform == nil {
			continue
		}
		combined = append(combined, rule.Rule{
			Base: defsecRule,
		})
	}

	return combined
}

func GetRuleById(id string) (*rule.Rule, error) {
	for _, r := range GetRegisteredRules() {
		if r.ID() == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with ID '%s'", id)
}

func GetRuleByLegacyID(legacyID string) (*rule.Rule, error) {
	modern := legacy.IDs[legacyID]
	for _, r := range registeredRules {
		if r.Base.Rule().LongID() == modern {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with legacyID '%s'", legacyID)
}
