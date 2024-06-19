package ignore

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

// Ignorer represents a function that checks if the rule should be ignored.
type Ignorer func(resultMeta types.Metadata, ignoredParam any) bool

type Rules []Rule

// Ignore checks if the rule should be ignored based on provided metadata, IDs, and ignorer functions.
func (r Rules) Ignore(m types.Metadata, ids []string, ignorers map[string]Ignorer) bool {
	return slices.ContainsFunc(r, func(r Rule) bool {
		return r.ignore(m, ids, ignorers)
	})
}

func (r Rules) shift() {
	var (
		currentRange *types.Range
		offset       int
	)

	for i := len(r) - 1; i > 0; i-- {
		currentRule, prevRule := r[i], r[i-1]

		if !prevRule.isStartLine {
			continue
		}

		if currentRange == nil {
			currentRange = &currentRule.rng
		}
		if prevRule.rng.GetStartLine()+1+offset == currentRule.rng.GetStartLine() {
			r[i-1].rng = *currentRange
			offset++
		} else {
			currentRange = nil
			offset = 0
		}
	}
}

// Rule represents a rule for ignoring vulnerabilities.
type Rule struct {
	rng         types.Range
	isStartLine bool
	sections    map[string]any
}

func (r Rule) ignore(m types.Metadata, ids []string, ignorers map[string]Ignorer) bool {
	matchMeta, ok := r.matchRange(&m)
	if !ok {
		return false
	}

	ignorers = lo.Assign(defaultIgnorers(ids), ignorers)

	for ignoreID, ignore := range ignorers {
		if param, exists := r.sections[ignoreID]; exists {
			if !ignore(*matchMeta, param) {
				return false
			}
		}
	}

	return true
}

func (r Rule) matchRange(m *types.Metadata) (*types.Metadata, bool) {
	metaHierarchy := m
	for metaHierarchy != nil {
		if r.rng.GetFilename() != metaHierarchy.Range().GetFilename() {
			metaHierarchy = metaHierarchy.Parent()
			continue
		}
		if metaHierarchy.Range().GetStartLine() == r.rng.GetStartLine()+1 ||
			metaHierarchy.Range().GetStartLine() == r.rng.GetStartLine() {
			return metaHierarchy, true
		}
		metaHierarchy = metaHierarchy.Parent()
	}

	return nil, false
}

func defaultIgnorers(ids []string) map[string]Ignorer {
	return map[string]Ignorer{
		"id": func(_ types.Metadata, param any) bool {
			id, ok := param.(string)
			if !ok {
				return false
			}
			if id == "*" || len(ids) == 0 {
				return true
			}

			return slices.ContainsFunc(ids, func(s string) bool {
				return MatchPattern(s, id)
			})
		},
		"exp": func(_ types.Metadata, param any) bool {
			expiry, ok := param.(time.Time)
			return ok && time.Now().Before(expiry)
		},
	}
}

// MatchPattern checks if the pattern string matches the input pattern.
// The wildcard '*' in the pattern matches any sequence of characters.
func MatchPattern(input, pattern string) bool {
	matched, err := regexp.MatchString(regexpFromPattern(pattern), input)
	return err == nil && matched
}

func regexpFromPattern(pattern string) string {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return "^" + pattern + "$"
	}
	var sb strings.Builder
	for i, literal := range parts {
		if i > 0 {
			sb.WriteString(".*")
		}
		sb.WriteString(regexp.QuoteMeta(literal))
	}
	return "^" + sb.String() + "$"
}
