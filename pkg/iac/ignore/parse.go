package ignore

import (
	"errors"
	"strings"
	"time"

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
func Parse(src, path string, parsers ...RuleSectionParser) Rules {
	var rules Rules
	for i, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		rng := types.NewRange(path, i+1, i+1, "", nil)
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

	sections := strings.Split(strings.TrimSpace(line), " ")
	for _, section := range sections {
		section := strings.TrimSpace(section)
		section = strings.TrimLeftFunc(section, func(r rune) bool {
			return r == '#' || r == '/' || r == '*'
		})

		section, exists := hasIgnoreRulePrefix(section)
		if !exists {
			continue
		}

		rule, err := parseComment(section, rng, parsers)
		if err != nil {
			log.Debug("Failed to parse rule", log.String("range", rng.String()), log.Err(err))
			continue
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

func parseComment(input string, rng types.Range, parsers []RuleSectionParser) (Rule, error) {
	rule := Rule{
		rng:      rng,
		sections: make(map[string]any),
	}

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
				rule.sections[idParser.Key()] = idParser.Param()
			}
		}

		for _, parser := range parsers {
			if parser.Key() != key {
				continue
			}

			if parser.Parse(val) {
				rule.sections[parser.Key()] = parser.Param()
			}
		}
	}

	if _, exists := rule.sections["id"]; !exists {
		return Rule{}, errors.New("rule section with the `ignore` key is required")
	}

	return rule, nil
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
