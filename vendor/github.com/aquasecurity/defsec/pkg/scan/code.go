package scan

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

type Code struct {
	lines []Line
}

type Line struct {
	Number      int
	Content     string
	IsCause     bool
	Annotation  string
	Truncated   bool
	Highlighted string
	FirstCause  bool
	LastCause   bool
}

func (c *Code) Lines() []Line {
	return c.lines
}

func (c *Code) IsCauseMultiline() bool {
	var count int
	for _, line := range c.lines {
		if line.IsCause {
			count++
			if count > 1 {
				return true
			}
		}
	}
	return false
}

// nolint
func (r *Result) GetCode(enableHighlighting bool) (*Code, error) {

	srcFS := r.Metadata().Range().GetFS()
	if srcFS == nil {
		return nil, fmt.Errorf("code unavailable: result was not mapped to a known filesystem")
	}

	innerRange := r.Range()
	outerRange := innerRange
	metadata := r.Metadata()
	for {
		if parent := metadata.Parent(); parent != nil && parent.Range().GetFilename() == metadata.Range().GetFilename() {
			outerRange = parent.Range()
			metadata = *parent
			continue
		}
		break
	}

	slashed := filepath.ToSlash(r.fsPath)
	slashed = strings.TrimPrefix(slashed, "/")

	content, err := fs.ReadFile(srcFS, slashed)
	if err != nil {
		return nil, fmt.Errorf("failed to read file from result filesystem (%#v): %w", srcFS, err)
	}

	hasAnnotation := r.Annotation() != ""

	code := Code{
		lines: nil,
	}

	rawLines := strings.Split(string(content), "\n")

	if outerRange.GetEndLine()-1 >= len(rawLines) || innerRange.GetStartLine() == 0 {
		return nil, fmt.Errorf("invalid line number")
	}

	shrink := outerRange.LineCount() > (innerRange.LineCount() + 10)

	if shrink {

		if outerRange.GetStartLine() < innerRange.GetStartLine() {
			code.lines = append(
				code.lines,
				Line{
					Content: rawLines[outerRange.GetStartLine()-1],
					Number:  outerRange.GetStartLine(),
				},
			)
			if outerRange.GetStartLine()+1 < innerRange.GetStartLine() {
				code.lines = append(
					code.lines,
					Line{
						Truncated: true,
						Number:    outerRange.GetStartLine() + 1,
					},
				)
			}
		}

		for lineNo := innerRange.GetStartLine(); lineNo <= innerRange.GetEndLine(); lineNo++ {

			line := Line{
				Number:  lineNo,
				Content: strings.TrimSuffix(rawLines[lineNo-1], "\r"),
				IsCause: true,
			}

			if hasAnnotation && lineNo == innerRange.GetStartLine() {
				line.Annotation = r.Annotation()
			}

			code.lines = append(code.lines, line)
		}

		if outerRange.GetEndLine() > innerRange.GetEndLine() {
			if outerRange.GetEndLine() > innerRange.GetEndLine()+1 {
				code.lines = append(
					code.lines,
					Line{
						Truncated: true,
						Number:    outerRange.GetEndLine() - 1,
					},
				)
			}
			code.lines = append(
				code.lines,
				Line{
					Content: rawLines[outerRange.GetEndLine()-1],
					Number:  outerRange.GetEndLine(),
				},
			)

		}

	} else {
		for lineNo := outerRange.GetStartLine(); lineNo <= outerRange.GetEndLine(); lineNo++ {

			line := Line{
				Number:  lineNo,
				Content: strings.TrimSuffix(rawLines[lineNo-1], "\r"),
				IsCause: lineNo >= innerRange.GetStartLine() && lineNo <= innerRange.GetEndLine(),
			}

			if hasAnnotation && lineNo == innerRange.GetStartLine() {
				line.Annotation = r.Annotation()
			}

			code.lines = append(code.lines, line)
		}
	}

	if enableHighlighting {
		code.lines = highlight(innerRange.GetLocalFilename(), code.lines)
	}
	return &code, nil
}
