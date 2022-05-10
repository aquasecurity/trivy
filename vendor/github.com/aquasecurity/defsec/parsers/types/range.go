package types

import "fmt"

type Range interface {
	GetFilename() string
	GetStartLine() int
	GetEndLine() int
	String() string
	IsMultiLine() bool
}

func NewRange(filename string, startLine int, endLine int) baseRange {
	return baseRange{
		filename:  filename,
		startLine: startLine,
		endLine:   endLine,
	}
}

type baseRange struct {
	filename  string
	startLine int
	endLine   int
}

func (r baseRange) GetFilename() string {
	return r.filename
}

func (r baseRange) GetStartLine() int {
	return r.startLine
}

func (r baseRange) GetEndLine() int {
	return r.endLine
}

func (r baseRange) IsMultiLine() bool {
	return r.startLine < r.endLine
}

func (r baseRange) String() string {
	if r.startLine != r.endLine {
		return fmt.Sprintf("%s:%d-%d", r.filename, r.startLine, r.endLine)
	}
	return fmt.Sprintf("%s:%d", r.filename, r.startLine)
}
