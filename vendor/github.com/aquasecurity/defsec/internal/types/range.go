package types

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

type Range interface {
	GetFilename() string
	GetLocalFilename() string
	GetSourcePrefix() string
	GetFS() fs.FS
	GetFSKey() string
	GetStartLine() int
	GetEndLine() int
	String() string
	IsMultiLine() bool
	LineCount() int
}

func NewRange(filename string, startLine int, endLine int, sourcePrefix string, srcFS fs.FS) baseRange {
	r := baseRange{
		filename:     filename,
		startLine:    startLine,
		endLine:      endLine,
		fs:           srcFS,
		fsKey:        CreateFSKey(srcFS),
		sourcePrefix: sourcePrefix,
	}
	return r
}

func NewRangeWithFSKey(filename string, startLine int, endLine int, sourcePrefix string, fsKey string, fs fs.FS) baseRange {
	r := baseRange{
		filename:     filename,
		startLine:    startLine,
		endLine:      endLine,
		fs:           fs,
		fsKey:        fsKey,
		sourcePrefix: sourcePrefix,
	}
	return r
}

type baseRange struct {
	filename     string
	startLine    int
	endLine      int
	sourcePrefix string
	fs           fs.FS
	fsKey        string
}

func (r baseRange) GetFSKey() string {
	return r.fsKey
}

func (r baseRange) LineCount() int {
	if r.endLine == 0 {
		return 0
	}
	return (r.endLine - r.startLine) + 1
}

func (r baseRange) GetFilename() string {
	if r.sourcePrefix == "" {
		return r.filename
	}
	return filepath.Join(r.sourcePrefix, r.filename)
}

func (r baseRange) GetLocalFilename() string {
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
		return fmt.Sprintf("%s:%d-%d", r.GetFilename(), r.startLine, r.endLine)
	}
	return fmt.Sprintf("%s:%d", r.GetFilename(), r.startLine)
}

func (r baseRange) GetFS() fs.FS {
	return r.fs
}

func (r baseRange) GetSourcePrefix() string {
	return r.sourcePrefix
}
