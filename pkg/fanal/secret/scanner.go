package secret

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var lineSep = []byte{'\n'}

const (
	// DefaultBufferSize is the default chunk size for streaming secret scanning
	// 64KB provides a good balance between memory usage and I/O efficiency
	// Larger buffers reduce I/O operations but use more memory
	// Smaller buffers use less memory but may increase I/O overhead
	DefaultBufferSize = 64 * 1024 // 64KB default buffer size

	// DefaultOverlap is the number of bytes to overlap between chunks
	// This ensures that secrets spanning chunk boundaries are not missed
	// Must be large enough to contain the longest possible secret pattern
	// 2KB should be sufficient for most secret types while keeping memory usage low
	DefaultOverlap = 2048 // 2KB overlap for boundary handling
)

type Scanner struct {
	logger      *log.Logger
	bufferSize  int
	overlapSize int
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

func MustCompileWithoutWordPrefix(str string) *Regexp {
	return MustCompile(fmt.Sprintf("%s(%s)", startWord, str))
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

func (s *Scanner) FindLocations(r Rule, content []byte) []Location {
	if r.Regex == nil {
		return nil
	}

	if r.SecretGroupName != "" {
		return s.FindSubmatchLocations(r, content)
	}

	var locs []Location
	indices := r.Regex.FindAllIndex(content, -1)
	for _, index := range indices {
		loc := Location{
			Start: index[0],
			End:   index[1],
		}

		if s.AllowLocation(r, content, loc) {
			continue
		}

		locs = append(locs, loc)
	}
	return locs
}

func (s *Scanner) FindSubmatchLocations(r Rule, content []byte) []Location {
	var submatchLocations []Location
	matchsIndices := r.Regex.FindAllSubmatchIndex(content, -1)
	for _, matchIndices := range matchsIndices {
		matchLocation := Location{
			// first two indexes are always start and end of the whole match
			Start: matchIndices[0],
			End:   matchIndices[1],
		}

		if s.AllowLocation(r, content, matchLocation) {
			continue
		}

		matchSubgroupsLocations := r.getMatchSubgroupsLocations(matchIndices)
		if len(matchSubgroupsLocations) > 0 {
			submatchLocations = append(submatchLocations, matchSubgroupsLocations...)
		}
	}
	return submatchLocations
}

func (s *Scanner) AllowLocation(r Rule, content []byte, loc Location) bool {
	match := string(content[loc.Start:loc.End])
	return s.Allow(match) || r.Allow(match)
}

func (r *Rule) getMatchSubgroupsLocations(matchLocs []int) []Location {
	var locations []Location
	for i, name := range r.Regex.SubexpNames() {
		if name == r.SecretGroupName {
			startLocIndex := 2 * i
			endLocIndex := startLocIndex + 1
			locations = append(locations, Location{
				Start: matchLocs[startLocIndex],
				End:   matchLocs[endLocIndex],
			})
		}
	}
	return locations
}

func (r *Rule) MatchPath(path string) bool {
	return r.Path == nil || r.Path.MatchString(path)
}

func (r *Rule) MatchKeywords(content []byte) bool {
	if len(r.Keywords) == 0 {
		return true
	}
	contentLower := bytes.ToLower(content)
	for _, kw := range r.Keywords {
		if bytes.Contains(contentLower, []byte(strings.ToLower(kw))) {
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

func ParseConfig(configPath string) (*Config, error) {
	// If no config is passed, use built-in rules and allow rules.
	if configPath == "" {
		return nil, nil
	}

	logger := log.WithPrefix("secret").With("config_path", configPath)
	f, err := os.Open(configPath)
	if errors.Is(err, os.ErrNotExist) {
		// If the specified file doesn't exist, it just uses built-in rules and allow rules.
		logger.Debug("No secret config detected")
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("file open error %s: %w", configPath, err)
	}
	defer f.Close()

	logger.Info("Loading the config file for secret scanning...")

	var config Config
	if err = yaml.NewDecoder(f).Decode(&config); err != nil {
		return nil, xerrors.Errorf("secrets config decode error: %w", err)
	}

	// Update severity for custom rules
	for i := range config.CustomRules {
		config.CustomRules[i].Severity = convertSeverity(logger, config.CustomRules[i].Severity)
	}

	return &config, nil
}

// convertSeverity checks the severity and converts it to uppercase or uses "UNKNOWN" for the wrong severity.
func convertSeverity(logger *log.Logger, severity string) string {
	switch strings.ToLower(severity) {
	case "low", "medium", "high", "critical", "unknown":
		return strings.ToUpper(severity)
	default:
		logger.Warn("Incorrect severity", log.String("severity", severity))
		return "UNKNOWN"
	}
}

// Option represents a functional option for configuring Scanner
type Option func(*Scanner)

// WithBufferSize configures the buffer size for streaming secret scanning
func WithBufferSize(size int) Option {
	return func(s *Scanner) {
		s.bufferSize = size
	}
}

// WithOverlapSize configures the overlap size between chunks
func WithOverlapSize(size int) Option {
	return func(s *Scanner) {
		s.overlapSize = size
	}
}

func NewScanner(config *Config, opts ...Option) Scanner {
	scanner := Scanner{
		logger:      log.WithPrefix(log.PrefixSecret),
		bufferSize:  DefaultBufferSize,
		overlapSize: DefaultOverlap,
	}

	// Use the default rules
	if config == nil {
		scanner.Global = &Global{
			Rules:      builtinRules,
			AllowRules: builtinAllowRules,
		}
		
		// Apply functional options
		for _, opt := range opts {
			opt(&scanner)
		}
		
		// Validate configuration
		if scanner.overlapSize >= scanner.bufferSize {
			scanner.logger.Warn("Overlap size exceeds buffer size, adjusting to 1/4 of buffer size",
				log.Int("overlap_size", scanner.overlapSize),
				log.Int("buffer_size", scanner.bufferSize))
			scanner.overlapSize = scanner.bufferSize / 4
		}
		
		return scanner
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
	rules := lo.Filter(enabledRules, func(v Rule, _ int) bool {
		return !slices.Contains(config.DisableRuleIDs, v.ID)
	})

	// Disable specified allow rules
	allowRules := append(builtinAllowRules, config.CustomAllowRules...)
	allowRules = lo.Filter(allowRules, func(v AllowRule, _ int) bool {
		return !slices.Contains(config.DisableAllowRuleIDs, v.ID)
	})

	scanner.Global = &Global{
		Rules:        rules,
		AllowRules:   allowRules,
		ExcludeBlock: config.ExcludeBlock,
	}
	
	// Apply functional options
	for _, opt := range opts {
		opt(&scanner)
	}
	
	// Validate configuration
	if scanner.overlapSize >= scanner.bufferSize {
		scanner.logger.Warn("Overlap size exceeds buffer size, adjusting to 1/4 of buffer size",
			log.Int("overlap_size", scanner.overlapSize),
			log.Int("buffer_size", scanner.bufferSize))
		scanner.overlapSize = scanner.bufferSize / 4
	}
	
	return scanner
}


type ScanArgs struct {
	FilePath string
	Content  io.Reader
	Binary   bool
}

type Match struct {
	Rule     Rule
	Location Location
}

// Scan performs secret scanning on the provided content using streaming approach
// This method processes files in configurable chunks to maintain constant memory usage
// regardless of file size, making it suitable for scanning very large files
//
// The streaming approach:
// 1. Reads file content in chunks (default 64KB)
// 2. Maintains overlap between chunks to catch secrets at boundaries
// 3. Processes each chunk independently for secrets
// 4. Adjusts line numbers to account for chunk positioning
// 5. Combines results from all chunks
func (s *Scanner) Scan(args ScanArgs) types.Secret {
	logger := s.logger.With(log.FilePath(args.FilePath))

	// Check if path is globally allowed (skip scanning entirely)
	if s.AllowPath(args.FilePath) {
		logger.Debug("Skipped secret scanning matching allowed paths")
		return types.Secret{
			FilePath: args.FilePath,
		}
	}

	// Perform streaming secret scanning
	// This approach keeps memory usage constant regardless of file size
	result := s.scanStream(args.FilePath, args.Content, args.Binary)
	return result
}

// scanStream performs streaming secret scanning by processing files in chunks
// This approach keeps memory usage constant (O(buffer_size)) regardless of file size
func (s *Scanner) scanStream(filePath string, reader io.Reader, binary bool) types.Secret {
	logger := s.logger.With(log.FilePath(filePath))

	// Initialize streaming context
	state := s.initializeStreamingContext()

	// Process file in chunks until EOF
	var allFindings []types.SecretFinding
	for {
		// Read next chunk with overlap from previous chunk
		chunk, isEOF, err := s.readNextChunk(reader, state)
		if err != nil {
			logger.Error("Failed to read content during streaming", log.Err(err))
			break
		}

		// Process the chunk for secrets if we have data
		if len(chunk) > 0 {
			chunkFindings := s.processChunkForSecrets(filePath, chunk, state, binary)
			allFindings = append(allFindings, chunkFindings...)
		}

		// Break if we've reached end of file
		if isEOF {
			break
		}

		// Prepare for next iteration by updating context
		s.updateStreamingContext(chunk, state)
	}

	// Return empty result if no secrets found
	if len(allFindings) == 0 {
		return types.Secret{}
	}

	// Clean up and sort findings
	allFindings = s.finalizeScanResults(allFindings)

	return types.Secret{
		FilePath: filePath,
		Findings: allFindings,
	}
}

// chunkState holds the state for streaming secret scanning
type chunkState struct {
	buffer        []byte // Main buffer for reading chunks
	overlapBuffer []byte // Buffer to store overlap from previous chunk
	lineOffset    int    // Running count of lines processed so far
}

// initializeStreamingContext sets up the initial state for streaming
func (s *Scanner) initializeStreamingContext() *chunkState {
	return &chunkState{
		buffer:        make([]byte, s.bufferSize),
		overlapBuffer: make([]byte, 0, s.overlapSize),
		lineOffset:    0,
	}
}

// readNextChunk reads the next chunk of data, incorporating overlap from the previous chunk
// Returns the chunk data, whether EOF was reached, and any error
func (s *Scanner) readNextChunk(reader io.Reader, state *chunkState) ([]byte, bool, error) {
	// Copy overlap data from previous chunk to beginning of buffer
	overlapLen := len(state.overlapBuffer)
	copy(state.buffer[:overlapLen], state.overlapBuffer)

	// Read new data after the overlap
	n, err := reader.Read(state.buffer[overlapLen:])
	isEOF := errors.Is(err, io.EOF)
	if n == 0 && isEOF {
		// Handle final overlap data if any exists
		if overlapLen > 0 {
			// Return the remaining overlap data as the final chunk
			return state.overlapBuffer, true, nil
		}
		// No more data to process
		return nil, true, nil
	}

	if err != nil && !isEOF {
		// Read error occurred
		return nil, false, xerrors.Errorf("failed to read next chunk: %w", err)
	}

	// Combine overlap and new data
	totalLen := overlapLen + n
	chunk := state.buffer[:totalLen]

	return chunk, isEOF, nil
}

// processChunkForSecrets scans a chunk for secrets and adjusts line numbers based on global offset
func (s *Scanner) processChunkForSecrets(filePath string, chunk []byte, state *chunkState, binary bool) []types.SecretFinding {
	// Scan the chunk
	chunkResult := s.scanChunk(filePath, chunk, binary)

	// Adjust line numbers to account for previous chunks
	for i := range chunkResult.Findings {
		// Adjust finding line numbers by adding the cumulative line offset
		chunkResult.Findings[i].StartLine += state.lineOffset
		chunkResult.Findings[i].EndLine += state.lineOffset

		// Adjust code context line numbers as well
		for j := range chunkResult.Findings[i].Code.Lines {
			chunkResult.Findings[i].Code.Lines[j].Number += state.lineOffset
		}
	}

	return chunkResult.Findings
}

// updateStreamingContext prepares the context for the next iteration
// This involves setting up overlap and updating line/chunk offsets
func (s *Scanner) updateStreamingContext(chunk []byte, state *chunkState) {
	totalLen := len(chunk)

	// Prepare overlap for next iteration to ensure secrets spanning chunk boundaries are detected
	if totalLen > s.overlapSize {
		// Save the last 'overlapSize' bytes for the next chunk
		state.overlapBuffer = state.overlapBuffer[:s.overlapSize]
		copy(state.overlapBuffer, chunk[totalLen-s.overlapSize:])

		// Update line and chunk offset based on non-overlapping part
		// We only count lines/bytes that won't be reprocessed in the next chunk
		nonOverlapPart := chunk[:totalLen-s.overlapSize]
		state.lineOffset += bytes.Count(nonOverlapPart, lineSep)
	} else {
		// If chunk is smaller than overlap size, keep entire chunk as overlap
		// This can happen with very small chunks near EOF
		state.overlapBuffer = state.overlapBuffer[:totalLen]
		copy(state.overlapBuffer, chunk)
		// Don't update offsets since entire chunk will be reprocessed
	}
}

// finalizeScanResults performs cleanup and sorting of all findings
func (s *Scanner) finalizeScanResults(findings []types.SecretFinding) []types.SecretFinding {
	// Remove duplicate findings that might occur at chunk boundaries
	// Note: Currently we preserve all findings to avoid losing legitimate secrets
	findings = s.deduplicateFindings(findings)

	// Sort findings for consistent output
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Match < findings[j].Match
	})

	return findings
}

func (s *Scanner) scanChunk(filePath string, content []byte, binary bool) types.Secret {
	logger := s.logger.With(log.FilePath(filePath))

	var censored []byte
	var copyCensored sync.Once
	var matched []Match

	var findings []types.SecretFinding
	globalExcludedBlocks := newBlocks(content, s.ExcludeBlock.Regexes)

	for _, rule := range s.Rules {
		ruleLogger := logger.With("rule_id", rule.ID)
		// Check if the file path should be scanned by this rule
		if !rule.MatchPath(filePath) {
			ruleLogger.Debug("Skipped secret scanning as non-compliant to the rule")
			continue
		}

		// Check if the file path should be allowed
		if rule.AllowPath(filePath) {
			ruleLogger.Debug("Skipped secret scanning as allowed")
			continue
		}

		// Check if the file content contains keywords and should be scanned
		if !rule.MatchKeywords(content) {
			continue
		}

		// Detect secrets
		locs := s.FindLocations(rule, content)
		if len(locs) == 0 {
			continue
		}

		localExcludedBlocks := newBlocks(content, rule.ExcludeBlock.Regexes)

		for _, loc := range locs {
			// Skip the secret if it is within excluded blocks.
			if globalExcludedBlocks.Match(loc) || localExcludedBlocks.Match(loc) {
				continue
			}

			matched = append(matched, Match{
				Rule:     rule,
				Location: loc,
			})
			copyCensored.Do(func() {
				censored = make([]byte, len(content))
				copy(censored, content)
			})
			censored = censorLocation(loc, censored)
		}
	}

	for _, match := range matched {
		finding := toFinding(match.Rule, match.Location, censored)
		// Rewrite unreadable fields for binary files
		if binary {
			finding.Match = fmt.Sprintf("Binary file %q matches a rule %q", filePath, match.Rule.Title)
			finding.Code = types.Code{}
		}
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		return types.Secret{}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Match < findings[j].Match
	})

	return types.Secret{
		FilePath: filePath,
		Findings: findings,
	}
}

// deduplicateFindings removes duplicate secret findings that may occur at chunk boundaries
func (s *Scanner) deduplicateFindings(findings []types.SecretFinding) []types.SecretFinding {
	return lo.UniqBy(findings, func(f types.SecretFinding) string {
		return fmt.Sprintf("%s:%d-%d:%s", f.RuleID, f.StartLine, f.EndLine, f.Match)
	})
}

func censorLocation(loc Location, input []byte) []byte {
	for i := loc.Start; i < loc.End; i++ {
		if input[i] != '\n' {
			input[i] = '*'
		}
	}
	return input
}

func toFinding(rule Rule, loc Location, content []byte) types.SecretFinding {
	startLine, endLine, code, matchLine := findLocation(loc.Start, loc.End, content)

	return types.SecretFinding{
		RuleID:    rule.ID,
		Category:  rule.Category,
		Severity:  lo.Ternary(rule.Severity == "", "UNKNOWN", rule.Severity),
		Title:     rule.Title,
		Match:     matchLine,
		StartLine: startLine,
		EndLine:   endLine,
		Code:      code,
	}
}

const (
	secretHighlightRadius = 2   // number of lines above + below each secret to include in code output
	maxLineLength         = 100 // all lines longer will be cut off
)

func findLocation(start, end int, content []byte) (int, int, types.Code, string) {
	startLineNum := bytes.Count(content[:start], lineSep)

	lineStart := bytes.LastIndex(content[:start], lineSep)
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}

	lineEnd := bytes.Index(content[start:], lineSep)
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += start
	}

	if lineEnd-lineStart > 100 {
		lineStart = lo.Ternary(start-lineStart-30 < 0, lineStart, start-30)
		lineEnd = lo.Ternary(end+20 > lineEnd, lineEnd, end+20)
	}
	matchLine := string(content[lineStart:lineEnd])
	endLineNum := startLineNum + bytes.Count(content[start:end], lineSep)

	var code types.Code

	lines := bytes.Split(content, lineSep)
	codeStart := lo.Ternary(startLineNum-secretHighlightRadius < 0, 0, startLineNum-secretHighlightRadius)
	codeEnd := lo.Ternary(endLineNum+secretHighlightRadius > len(lines), len(lines), endLineNum+secretHighlightRadius)

	rawLines := lines[codeStart:codeEnd]
	var foundFirst bool
	for i, rawLine := range rawLines {
		realLine := codeStart + i
		inCause := realLine >= startLineNum && realLine <= endLineNum

		var strRawLine string
		if len(rawLine) > maxLineLength {
			strRawLine = lo.Ternary(inCause, matchLine, string(rawLine[:maxLineLength]))
		} else {
			strRawLine = string(rawLine)
		}

		code.Lines = append(code.Lines, types.Line{
			Number:      codeStart + i + 1,
			Content:     strRawLine,
			IsCause:     inCause,
			Highlighted: strRawLine,
			FirstCause:  !foundFirst && inCause,
			LastCause:   false,
		})
		foundFirst = foundFirst || inCause
	}
	if len(code.Lines) > 0 {
		for i := len(code.Lines) - 1; i >= 0; i-- {
			if code.Lines[i].IsCause {
				code.Lines[i].LastCause = true
				break
			}
		}
	}

	return startLineNum + 1, endLineNum + 1, code, matchLine
}
