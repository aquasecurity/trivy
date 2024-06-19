package ignore

import (
	"errors"
	"strings"
	"time"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// RuleSectionParser defines the interface for parsing ignore rules.
type RuleSectionParser interface {
	Key() string
	Parse(string) bool
	Param() any
}

// Parse parses the configuration file and returns the Rules
func Parse(src, path, sourcePrefix string, parsers ...RuleSectionParser) Rules {
	var rules Rules
	for i, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		rng := types.NewRange(path, i+1, i+1, sourcePrefix, nil)
		lineIgnores := parseLine(line, rng, parsers)
		for _, lineIgnore := range lineIgnores {
			rules = append(rules, lineIgnore)
		}
	}

	rules.shift()

	return rules
}

func parseLine(line string, rng types.Range, parsers []RuleSectionParser) []Rule {
	var rules []Rule

	parts := strings.Split(strings.TrimSpace(line), " ")
	parts = lo.FilterMap(parts, func(part string, _ int) (string, bool) {
		part = strings.TrimSpace(part)
		part = strings.TrimLeftFunc(part, func(r rune) bool {
			return r == '#' || r == '/' || r == '*'
		})

		return part, part != ""
	})

	for i, part := range parts {
		part, exists := hasIgnoreRulePrefix(part)
		if !exists {
			continue
		}

		sections, err := parseRuleSections(part, rng, parsers)
		if err != nil {
			log.Debug("Failed to parse rule", log.String("range", rng.String()), log.Err(err))
			continue
		}

		rule := Rule{
			rng:         rng,
			isStartLine: i == 0 || (len(rules) > 0 && rules[0].isStartLine),
			sections:    sections,
		}

		rules = append(rules, rule)
	}

	return rules
}

func hasIgnoreRulePrefix(s string) (string, bool) {
	for _, prefix := range []string{
		"tfsec:",
		"trivy:",
	} {
		if after, found := strings.CutPrefix(s, prefix); found {
			return after, true
		}
	}

	return "", false
}

func parseRuleSections(input string, rng types.Range, parsers []RuleSectionParser) (map[string]any, error) {
	sections := make(map[string]any)

	parsers = append(parsers, &expiryDateParser{
		rng: rng,
	})

	segments := strings.Split(input, ":")

	for i := 0; i < len(segments)-1; i += 2 {
		key := segments[i]
		val := segments[i+1]
		if key == "ignore" {
			// special case, because id and parameters are in the same section
			idParser := &checkIDParser{
				StringMatchParser{SectionKey: "id"},
			}
			if idParser.Parse(val) {
				sections[idParser.Key()] = idParser.Param()
			}
		}

		for _, parser := range parsers {
			if parser.Key() != key {
				continue
			}

			if parser.Parse(val) {
				sections[parser.Key()] = parser.Param()
			}
		}
	}

	if _, exists := sections["id"]; !exists {
		return nil, errors.New("rule section with the `ignore` key is required")
	}

	return sections, nil
}

type StringMatchParser struct {
	SectionKey string
	param      string
}

func (s *StringMatchParser) Key() string {
	return s.SectionKey
}

func (s *StringMatchParser) Parse(str string) bool {
	s.param = str
	return str != ""
}

func (s *StringMatchParser) Param() any {
	return s.param
}

type checkIDParser struct {
	StringMatchParser
}

func (s *checkIDParser) Parse(str string) bool {
	if idx := strings.Index(str, "["); idx != -1 {
		str = str[:idx]
	}
	return s.StringMatchParser.Parse(str)
}

type expiryDateParser struct {
	rng    types.Range
	expiry time.Time
}

func (s *expiryDateParser) Key() string {
	return "exp"
}

func (s *expiryDateParser) Parse(str string) bool {
	parsed, err := time.Parse("2006-01-02", str)
	if err != nil {
		log.Debug("Incorrect time to ignore is specified", log.String("time", str))
		parsed = time.Time{}
	} else if time.Now().After(parsed) {
		log.Debug("Ignore rule time has expired for location", log.String("range", s.rng.String()))
	}

	s.expiry = parsed
	return true
}

func (s *expiryDateParser) Param() any {
	return s.expiry
}
