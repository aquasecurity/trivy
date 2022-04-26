package secret

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
)

var lineSep = []byte{'\n'}

type Scanner struct {
	*Global
}

type Config struct {
	// Enable only specified built-in rules. If only one ID is specified, all other rules are disabled.
	// All the built-in rules are enabled if this field is not specified. It doesn't affect custom rules.
	EnableBuiltinRuleIDs []string `yaml:"enable-builtin-rules"`

	// Disable rules. It is applied to enabled IDs.
	DisableRuleIDs []string `yaml:"disable-rules"`

	// Disable allow rules.
	DisableAllowRuleIDs []string `yaml:"disable-allow-rules"`

	CustomRules      []Rule       `yaml:"rules"`
	CustomAllowRules AllowRules   `yaml:"allow-rules"`
	ExcludeBlock     ExcludeBlock `yaml:"exclude-block"`
}

type Global struct {
	Rules        []Rule
	AllowRules   AllowRules
	ExcludeBlock ExcludeBlock
}

// Allow checks if the match is allowed
func (g Global) Allow(match string) bool {
	return g.AllowRules.Allow(match)
}

// AllowPath checks if the path is allowed
func (g Global) AllowPath(path string) bool {
	return g.AllowRules.AllowPath(path)
}

// Regexp adds unmarshalling from YAML for regexp.Regexp
type Regexp struct {
	*regexp.Regexp
}

func MustCompile(str string) *Regexp {
	return &Regexp{regexp.MustCompile(str)}
}

// UnmarshalYAML unmarshals YAML into a regexp.Regexp
func (r *Regexp) UnmarshalYAML(value *yaml.Node) error {
	var v string
	if err := value.Decode(&v); err != nil {
		return err
	}
	regex, err := regexp.Compile(v)
	if err != nil {
		return xerrors.Errorf("regexp compile error: %w", err)
	}

	r.Regexp = regex
	return nil
}

type Rule struct {
	ID              string                   `yaml:"id"`
	Category        types.SecretRuleCategory `yaml:"category"`
	Title           string                   `yaml:"title"`
	Severity        string                   `yaml:"severity"`
	Regex           *Regexp                  `yaml:"regex"`
	Keywords        []string                 `yaml:"keywords"`
	Path            *Regexp                  `yaml:"path"`
	AllowRules      AllowRules               `yaml:"allow-rules"`
	ExcludeBlock    ExcludeBlock             `yaml:"exclude-block"`
	SecretGroupName string                   `yaml:"secret-group-name"`
}

func (r *Rule) FindLocations(content []byte) []Location {
	if r.Regex == nil {
		return nil
	}
	var indices [][]int
	if r.SecretGroupName == "" {
		indices = r.Regex.FindAllIndex(content, -1)
	} else {
		indices = r.FindSubmatchIndices(content)
	}

	var locs []Location
	for _, index := range indices {
		locs = append(locs, Location{
			Start: index[0],
			End:   index[1],
		})
	}
	return locs
}

func (r *Rule) FindSubmatchIndices(content []byte) [][]int {
	var indices [][]int
	matchsLocs := r.Regex.FindAllSubmatchIndex(content, -1)
	for _, matchLocs := range matchsLocs {
		for i, name := range r.Regex.SubexpNames() {
			if name == r.SecretGroupName {
				startLocIndex := 2 * i
				endLocIndex := startLocIndex + 1
				indices = append(indices, []int{matchLocs[startLocIndex], matchLocs[endLocIndex]})
			}
		}
	}
	return indices
}

func (r *Rule) MatchPath(path string) bool {
	return r.Path == nil || r.Path.MatchString(path)
}

func (r *Rule) MatchKeywords(content []byte) bool {
	if len(r.Keywords) == 0 {
		return true
	}

	for _, kw := range r.Keywords {
		if bytes.Contains(bytes.ToLower(content), []byte(strings.ToLower(kw))) {
			return true
		}
	}

	return false
}

func (r *Rule) AllowPath(path string) bool {
	return r.AllowRules.AllowPath(path)
}

func (r *Rule) Allow(match string) bool {
	return r.AllowRules.Allow(match)
}

type AllowRule struct {
	ID          string  `yaml:"id"`
	Description string  `yaml:"description"`
	Regex       *Regexp `yaml:"regex"`
	Path        *Regexp `yaml:"path"`
}

type AllowRules []AllowRule

func (rules AllowRules) AllowPath(path string) bool {
	for _, rule := range rules {
		if rule.Path != nil && rule.Path.MatchString(path) {
			return true
		}
	}
	return false
}

func (rules AllowRules) Allow(match string) bool {
	for _, rule := range rules {
		if rule.Regex != nil && rule.Regex.MatchString(match) {
			return true
		}
	}
	return false
}

type ExcludeBlock struct {
	Description string    `yaml:"description"`
	Regexes     []*Regexp `yaml:"regexes"`
}

type Location struct {
	Start int
	End   int
}

func (l Location) Match(loc Location) bool {
	return l.Start <= loc.Start && loc.End <= l.End
}

type Blocks struct {
	content []byte
	regexes []*Regexp
	locs    []Location
	once    *sync.Once
}

func newBlocks(content []byte, regexes []*Regexp) Blocks {
	return Blocks{
		content: content,
		regexes: regexes,
		once:    new(sync.Once),
	}
}

func (b *Blocks) Match(block Location) bool {
	b.once.Do(b.find)
	for _, loc := range b.locs {
		if loc.Match(block) {
			return true
		}
	}
	return false
}

func (b *Blocks) find() {
	for _, regex := range b.regexes {
		results := regex.FindAllIndex(b.content, -1)
		if len(results) == 0 {
			continue
		}
		for _, r := range results {
			b.locs = append(b.locs, Location{
				Start: r[0],
				End:   r[1],
			})
		}
	}
}

func NewScanner(configPath string) (Scanner, error) {
	// Set default values
	global := Global{
		Rules:      builtinRules,
		AllowRules: builtinAllowRules,
	}

	// If no config is passed, use built-in rules and allow rules.
	if configPath == "" {
		return Scanner{&global}, nil
	}

	f, err := os.Open(configPath)
	if errors.Is(err, os.ErrNotExist) {
		// If the specified file doesn't exist, it just uses built-in rules and allow rules.
		log.Logger.Debugf("No secret config detected: %s", configPath)
		return Scanner{&global}, nil
	} else if err != nil {
		return Scanner{}, xerrors.Errorf("file open error %s: %w", configPath, err)
	}
	defer f.Close()

	log.Logger.Infof("Loading %s for secret scanning...", configPath)

	// reset global
	global = Global{}

	var config Config
	if err = yaml.NewDecoder(f).Decode(&config); err != nil {
		return Scanner{}, xerrors.Errorf("secrets config decode error: %w", err)
	}

	enabledRules := builtinRules
	if len(config.EnableBuiltinRuleIDs) != 0 {
		// Enable only specified built-in rules
		enabledRules = lo.Filter(builtinRules, func(v Rule, _ int) bool {
			return slices.Contains(config.EnableBuiltinRuleIDs, v.ID)
		})
	}

	// Custom rules are enabled regardless of "enable-builtin-rules".
	enabledRules = append(enabledRules, config.CustomRules...)

	// Disable specified rules
	global.Rules = lo.Filter(enabledRules, func(v Rule, _ int) bool {
		return !slices.Contains(config.DisableRuleIDs, v.ID)
	})

	// Disable specified allow rules
	allowRules := append(builtinAllowRules, config.CustomAllowRules...)
	global.AllowRules = lo.Filter(allowRules, func(v AllowRule, _ int) bool {
		return !slices.Contains(config.DisableAllowRuleIDs, v.ID)
	})

	global.ExcludeBlock = config.ExcludeBlock

	return Scanner{Global: &global}, nil
}

type ScanArgs struct {
	FilePath string
	Content  []byte
}

func (s Scanner) Scan(args ScanArgs) types.Secret {
	// Global allowed paths
	if s.AllowPath(args.FilePath) {
		return types.Secret{
			FilePath: args.FilePath,
		}
	}

	var findings []types.SecretFinding
	globalExcludedBlocks := newBlocks(args.Content, s.ExcludeBlock.Regexes)
	for _, rule := range s.Rules {
		// Check if the file path should be scanned by this rule
		if !rule.MatchPath(args.FilePath) {
			continue
		}

		// Check if the file path should be allowed
		if rule.AllowPath(args.FilePath) {
			continue
		}

		// Check if the file content contains keywords and should be scanned
		if !rule.MatchKeywords(args.Content) {
			continue
		}

		// Detect secrets
		locs := rule.FindLocations(args.Content)
		if len(locs) == 0 {
			continue
		}

		localExcludedBlocks := newBlocks(args.Content, rule.ExcludeBlock.Regexes)
		for _, loc := range locs {
			match := string(args.Content[loc.Start:loc.End])

			// Apply global and local allow rules.
			if s.Allow(match) || rule.Allow(match) {
				continue
			}

			// Skip the secret if it is within excluded blocks.
			if globalExcludedBlocks.Match(loc) || localExcludedBlocks.Match(loc) {
				continue
			}

			findings = append(findings, toFinding(rule, loc, args.Content))
		}
	}

	if len(findings) == 0 {
		return types.Secret{}
	}

	return types.Secret{
		FilePath: args.FilePath,
		Findings: findings,
	}
}

func toFinding(rule Rule, loc Location, content []byte) types.SecretFinding {
	startLine, endLine, matchLine := findLocation(loc.Start, loc.End, content)
	return types.SecretFinding{
		RuleID:    rule.ID,
		Category:  rule.Category,
		Severity:  rule.Severity,
		Title:     rule.Title,
		StartLine: startLine,
		EndLine:   endLine,
		Match:     matchLine,
	}
}

func findLocation(start, end int, content []byte) (int, int, string) {
	startLineNum := bytes.Count(content[:start], lineSep) + 1
	endLineNum := startLineNum // TODO: support multi lines

	lineStart := bytes.LastIndex(content[:start], lineSep)
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart += 1
	}

	lineEnd := bytes.Index(content[start:], lineSep)
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}

	match := string(content[start:end])
	matchLine := string(content[lineStart:lineEnd])
	if len(matchLine) > 100 {
		truncatedLineStart := lo.Ternary(start-30 < 0, 0, start-30)
		truncatedLineEnd := lo.Ternary(end+20 > len(content), len(content), end+20)
		matchLine = string(content[truncatedLineStart:truncatedLineEnd])
	}

	// Mask credentials
	matchLine = strings.TrimSpace(strings.ReplaceAll(matchLine, match, "*****"))

	return startLineNum, endLineNum, matchLine
}
