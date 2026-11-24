package types

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"path"
)

func NewRange(filename string, startLine, endLine int, sourcePrefix string, srcFS fs.FS) Range {
	return newRange(filename, startLine, endLine, sourcePrefix, CreateFSKey(srcFS), srcFS, false)
}

func NewRangeWithLogicalSource(filename string, startLine, endLine int, sourcePrefix string, srcFS fs.FS) Range {
	return newRange(filename, startLine, endLine, sourcePrefix, CreateFSKey(srcFS), srcFS, true)
}

func NewRangeWithFSKey(filename string, startLine, endLine int, sourcePrefix, fsKey string, fsys fs.FS) Range {
	return newRange(filename, startLine, endLine, sourcePrefix, fsKey, fsys, false)
}

func newRange(filename string, startLine, endLine int, sourcePrefix, fsKey string, fsys fs.FS, isLogical bool) Range {
	return Range{
		filename:        filename,
		startLine:       startLine,
		endLine:         endLine,
		fs:              fsys,
		fsKey:           fsKey,
		sourcePrefix:    sourcePrefix,
		isLogicalSource: isLogical,
	}
}

type Range struct {
	filename        string
	startLine       int
	endLine         int
	sourcePrefix    string
	isLogicalSource bool
	fs              fs.FS
	fsKey           string
}

// rangeJSON mirrors the unexported fields of [Range].
// The file system is not serialized and is restored by the caller if needed.
type rangeJSON struct {
	Filename        string `json:"filename"`
	StartLine       int    `json:"startLine"`
	EndLine         int    `json:"endLine"`
	SourcePrefix    string `json:"sourcePrefix"`
	FSKey           string `json:"fsKey"`
	IsLogicalSource bool   `json:"isLogicalSource"`
}

func (r Range) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, rangeJSON{
		Filename:        r.filename,
		StartLine:       r.startLine,
		EndLine:         r.endLine,
		SourcePrefix:    r.sourcePrefix,
		FSKey:           r.fsKey,
		IsLogicalSource: r.isLogicalSource,
	})
}

func (r *Range) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var raw rangeJSON
	if err := json.UnmarshalDecode(dec, &raw); err != nil {
		return err
	}

	r.filename = raw.Filename
	r.startLine = raw.StartLine
	r.endLine = raw.EndLine
	r.sourcePrefix = raw.SourcePrefix
	r.fsKey = raw.FSKey
	r.isLogicalSource = raw.IsLogicalSource
	return nil
}

func (r Range) GetFSKey() string {
	return r.fsKey
}

func (r Range) LineCount() int {
	if r.endLine == 0 {
		return 0
	}
	return (r.endLine - r.startLine) + 1
}

func (r Range) GetFilename() string {
	if r.sourcePrefix == "" {
		return r.filename
	}
	if r.isLogicalSource {
		return fmt.Sprintf("%s:%s", r.sourcePrefix, r.filename)
	}
	return path.Join(r.sourcePrefix, r.filename)
}

func (r Range) GetLocalFilename() string {
	return r.filename
}

func (r Range) GetStartLine() int {
	return r.startLine
}

func (r Range) GetEndLine() int {
	return r.endLine
}

func (r Range) IsMultiLine() bool {
	return r.startLine < r.endLine
}

func (r Range) String() string {
	if r.startLine != r.endLine {
		return fmt.Sprintf("%s:%d-%d", r.GetFilename(), r.startLine, r.endLine)
	}
	if r.startLine == 0 && r.endLine == 0 {
		return r.GetFilename()
	}
	return fmt.Sprintf("%s:%d", r.GetFilename(), r.startLine)
}

func (r Range) GetFS() fs.FS {
	return r.fs
}

func (r Range) GetSourcePrefix() string {
	return r.sourcePrefix
}

func (r Range) Validate() error {
	if r.startLine < 0 || r.endLine < 0 || r.startLine > r.endLine {
		return fmt.Errorf("invalid range: %s", r.String())
	}
	return nil
}

// Includes returns true if 'other' is strictly inside 'r'.
func (r Range) Includes(other Range) bool {
	return r.startLine < other.startLine && r.endLine > other.endLine
}

// Covers returns true if 'r' fully contains 'other'.
func (r Range) Covers(other Range) bool {
	return r.startLine <= other.startLine && r.endLine >= other.endLine
}
