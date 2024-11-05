package types

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
)

func NewRange(filename string, startLine, endLine int, sourcePrefix string, srcFS fs.FS) Range {
	r := Range{
		filename:     filename,
		startLine:    startLine,
		endLine:      endLine,
		fs:           srcFS,
		fsKey:        CreateFSKey(srcFS),
		sourcePrefix: sourcePrefix,
	}
	return r
}

func NewRangeWithLogicalSource(filename string, startLine int, endLine int, sourcePrefix string,
	srcFS fs.FS) Range {
	r := Range{
		filename:        filename,
		startLine:       startLine,
		endLine:         endLine,
		fs:              srcFS,
		fsKey:           CreateFSKey(srcFS),
		sourcePrefix:    sourcePrefix,
		isLogicalSource: true,
	}
	return r
}

func NewRangeWithFSKey(filename string, startLine, endLine int, sourcePrefix, fsKey string, fsys fs.FS) Range {
	r := Range{
		filename:     filename,
		startLine:    startLine,
		endLine:      endLine,
		fs:           fsys,
		fsKey:        fsKey,
		sourcePrefix: sourcePrefix,
	}
	return r
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

func (r Range) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"filename":        r.filename,
		"startLine":       r.startLine,
		"endLine":         r.endLine,
		"sourcePrefix":    r.sourcePrefix,
		"fsKey":           r.fsKey,
		"isLogicalSource": r.isLogicalSource,
	})
}

func (r *Range) UnmarshalJSON(data []byte) error {
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["filename"] != nil {
		r.filename = keys["filename"].(string)
	}
	if keys["startLine"] != nil {
		r.startLine = int(keys["startLine"].(float64))
	}
	if keys["endLine"] != nil {
		r.endLine = int(keys["endLine"].(float64))
	}
	if keys["sourcePrefix"] != nil {
		r.sourcePrefix = keys["sourcePrefix"].(string)
	}
	if keys["fsKey"] != nil {
		r.fsKey = keys["fsKey"].(string)
	}
	if keys["isLogicalSource"] != nil {
		r.isLogicalSource = keys["isLogicalSource"].(bool)
	}
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
