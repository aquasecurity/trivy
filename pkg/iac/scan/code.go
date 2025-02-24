package scan

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Code struct {
	Lines []Line
}

func (c *Code) truncateLines(maxLines int) {
	previouslyTruncated := maxLines-1 > 0 && c.Lines[maxLines-2].Truncated
	if maxLines-1 > 0 && c.Lines[maxLines-1].LastCause {
		c.Lines[maxLines-2].LastCause = true
	}
	c.Lines[maxLines-1] = Line{
		Truncated: true,
		Number:    c.Lines[maxLines-1].Number,
	}
	if previouslyTruncated {
		c.Lines = c.Lines[:maxLines-1]
	} else {
		c.Lines = c.Lines[:maxLines]
	}
}

func (c *Code) markFirstAndLastCauses() {
	var isFirst bool
	var isLast bool

	for i, line := range c.Lines {
		if line.IsCause && !isFirst {
			c.Lines[i].FirstCause = true
			isFirst = true
		}

		if isFirst && !line.IsCause && i > 0 {
			c.Lines[i-1].LastCause = true
			isLast = true
			break
		}
	}

	if !isLast && len(c.Lines) > 0 {
		c.Lines[len(c.Lines)-1].LastCause = true
	}
}

type Line struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted,omitempty"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

func (c *Code) IsCauseMultiline() bool {
	var count int
	for _, line := range c.Lines {
		if line.IsCause {
			count++
			if count > 1 {
				return true
			}
		}
	}
	return false
}

const (
	darkTheme  = "solarized-dark256"
	lightTheme = "github"
)

type codeSettings struct {
	theme              string
	allowTruncation    bool
	maxLines           int
	includeHighlighted bool
}

var defaultCodeSettings = codeSettings{
	theme:              darkTheme,
	allowTruncation:    true,
	maxLines:           10,
	includeHighlighted: true,
}

type CodeOption func(*codeSettings)

func OptionCodeWithTheme(theme string) CodeOption {
	return func(s *codeSettings) {
		s.theme = theme
	}
}

func OptionCodeWithDarkTheme() CodeOption {
	return func(s *codeSettings) {
		s.theme = darkTheme
	}
}

func OptionCodeWithLightTheme() CodeOption {
	return func(s *codeSettings) {
		s.theme = lightTheme
	}
}

func OptionCodeWithTruncation(truncate bool) CodeOption {
	return func(s *codeSettings) {
		s.allowTruncation = truncate
	}
}

func OptionCodeWithMaxLines(lines int) CodeOption {
	return func(s *codeSettings) {
		s.maxLines = lines
	}
}

func OptionCodeWithHighlighted(include bool) CodeOption {
	return func(s *codeSettings) {
		s.includeHighlighted = include
	}
}

func (r *Result) GetCode(opts ...CodeOption) (*Code, error) {
	settings := defaultCodeSettings
	for _, opt := range opts {
		opt(&settings)
	}

	fsys := r.Metadata().Range().GetFS()
	if fsys == nil {
		return nil, errors.New("code unavailable: result was not mapped to a known filesystem")
	}

	innerRange := r.metadata.Range()
	if err := innerRange.Validate(); err != nil {
		return nil, err
	}

	if innerRange.GetStartLine() == 0 {
		return nil, fmt.Errorf("inner range has invalid start line: %s", innerRange.String())
	}

	outerRange := r.getOuterRange()
	if err := outerRange.Validate(); err != nil {
		return nil, err
	}

	filePath := strings.TrimPrefix(filepath.ToSlash(r.fsPath), "/")
	rawLines, err := readLinesFromFile(fsys, filePath, outerRange.GetStartLine(), outerRange.GetEndLine())
	if err != nil {
		return nil, err
	}

	if outerRange.GetEndLine()-outerRange.GetStartLine() > len(rawLines) {
		return nil, fmt.Errorf("invalid outer range: %s", outerRange.String())
	}

	highlightedLines := r.getHighlightedLines(outerRange, innerRange, rawLines, settings)

	var code Code

	shrink := settings.allowTruncation && outerRange.LineCount() > (innerRange.LineCount()+10)

	if shrink {
		code.Lines = r.getTruncatedLines(outerRange, innerRange, rawLines, highlightedLines)
	} else {
		code.Lines = r.getAllLines(outerRange, innerRange, rawLines, highlightedLines)
	}

	if settings.allowTruncation && len(code.Lines) > settings.maxLines && settings.maxLines > 0 {
		code.truncateLines(settings.maxLines)
	}

	code.markFirstAndLastCauses()

	return &code, nil
}

func (r *Result) getHighlightedLines(outerRange, innerRange iacTypes.Range, rawLines []string, settings codeSettings) []string {

	highlightedLines := make([]string, len(rawLines))
	if !settings.includeHighlighted {
		return highlightedLines
	}

	content := strings.Join(rawLines, "\n")
	fsKey := iacTypes.CreateFSKey(innerRange.GetFS())
	highlightedLines = highlight(fsKey, innerRange.GetLocalFilename(),
		outerRange.GetStartLine(), outerRange.GetEndLine(), content, settings.theme)

	if len(highlightedLines) < len(rawLines) {
		return rawLines
	}

	return highlightedLines
}

func (r *Result) getOuterRange() iacTypes.Range {
	outer := r.Metadata().Range()
	for parent := r.Metadata().Parent(); parent != nil &&
		parent.Range().GetFilename() == outer.GetFilename() &&
		parent.Range().GetStartLine() > 0; parent = parent.Parent() {
		outer = parent.Range()
	}
	return outer
}

func (r *Result) getTruncatedLines(outerRange, innerRange iacTypes.Range, rawLines, highlightedLines []string) []Line {
	var lines []Line

	if outerRange.GetStartLine() < innerRange.GetStartLine() {
		lines = append(lines, Line{
			Content:     rawLines[0],
			Highlighted: highlightedLines[0],
			Number:      outerRange.GetStartLine(),
		})
		if outerRange.GetStartLine()+1 < innerRange.GetStartLine() {
			lines = append(lines, Line{
				Truncated: true,
				Number:    outerRange.GetStartLine() + 1,
			})
		}
	}

	for lineNo := innerRange.GetStartLine() - outerRange.GetStartLine(); lineNo <= innerRange.GetEndLine()-outerRange.GetStartLine(); lineNo++ {
		if lineNo >= len(rawLines) || lineNo >= len(highlightedLines) {
			break
		}

		line := Line{
			Number:      lineNo + outerRange.GetStartLine(),
			Content:     strings.TrimSuffix(rawLines[lineNo], "\r"),
			Highlighted: strings.TrimSuffix(highlightedLines[lineNo], "\r"),
			IsCause:     true,
		}

		if r.Annotation() != "" && lineNo == innerRange.GetStartLine()-outerRange.GetStartLine()-1 {
			line.Annotation = r.Annotation()
		}

		lines = append(lines, line)
	}

	if outerRange.GetEndLine() > innerRange.GetEndLine() {
		if outerRange.GetEndLine() > innerRange.GetEndLine()+1 {
			lines = append(lines, Line{
				Truncated: true,
				Number:    outerRange.GetEndLine() - 1,
			})
		}
		lines = append(lines, Line{
			Content:     rawLines[outerRange.GetEndLine()-outerRange.GetStartLine()],
			Highlighted: highlightedLines[outerRange.GetEndLine()-outerRange.GetStartLine()],
			Number:      outerRange.GetEndLine(),
		})
	}

	return lines
}

func (r *Result) getAllLines(outerRange, innerRange iacTypes.Range, rawLines, highlightedLines []string) []Line {
	lines := make([]Line, 0, outerRange.GetEndLine()-outerRange.GetStartLine()+1)

	for lineNo := 0; lineNo <= outerRange.GetEndLine()-outerRange.GetStartLine(); lineNo++ {
		line := Line{
			Number:      lineNo + outerRange.GetStartLine(),
			Content:     strings.TrimSuffix(rawLines[lineNo], "\r"),
			Highlighted: strings.TrimSuffix(highlightedLines[lineNo], "\r"),
			IsCause: lineNo >= innerRange.GetStartLine()-outerRange.GetStartLine() &&
				lineNo <= innerRange.GetEndLine()-outerRange.GetStartLine(),
		}

		if r.Annotation() != "" && lineNo == innerRange.GetStartLine()-outerRange.GetStartLine()-1 {
			line.Annotation = r.Annotation()
		}

		lines = append(lines, line)
	}

	return lines
}

func readLinesFromFile(fsys fs.FS, path string, from, to int) ([]string, error) {
	slashedPath := strings.TrimPrefix(filepath.ToSlash(path), "/")

	file, err := fsys.Open(slashedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file from result filesystem: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	rawLines := make([]string, 0, to-from+1)

	for lineNum := 0; scanner.Scan() && lineNum < to; lineNum++ {
		if lineNum >= from-1 {
			rawLines = append(rawLines, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan file: %w", err)
	}

	return rawLines, nil
}
