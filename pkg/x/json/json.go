package json

import (
	"bytes"
	"io"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// lineReader is a custom reader that tracks line numbers.
type lineReader struct {
	r    io.Reader
	line int
}

// newLineReader creates a new line reader.
func newLineReader(r io.Reader) *lineReader {
	return &lineReader{
		r:    r,
		line: 1,
	}
}

func (lr *lineReader) Read(p []byte) (n int, err error) {
	n, err = lr.r.Read(p)
	if n > 0 {
		// Count the number of newlines in the read buffer
		lr.line += bytes.Count(p[:n], []byte("\n"))
	}
	return n, err
}

func (lr *lineReader) Line() int {
	return lr.line
}

func Unmarshal(data []byte, v any) error {
	return UnmarshalRead(bytes.NewBuffer(data), v)
}

func UnmarshalRead(r io.Reader, v any) error {
	lr := newLineReader(r)
	unmarshalers := unmarshalerWithObjectLocation(lr)
	return json.UnmarshalRead(lr, v, json.WithUnmarshalers(unmarshalers))
}

// Location is wrap of types.Location.
// This struct is required when you need to detect location of your object from json file.
type Location struct {
	types.Location
}

func (l *Location) SetLocation(location types.Location) {
	l.Location = location
}

// ObjectLocation is required when you need to save Location for your struct.
type ObjectLocation interface {
	SetLocation(location types.Location)
}

// unmarshalerWithObjectLocation creates json.Unmarshaler for ObjectLocation to save object location into xjson.Location
// To use UnmarshalerWithObjectLocation for primitive types, you must implement the UnmarshalerFrom interface for those objects.
// cf. https://pkg.go.dev/github.com/go-json-experiment/json#UnmarshalerFrom
func unmarshalerWithObjectLocation(r *lineReader) *json.Unmarshalers {
	visited := set.New[any]()
	return unmarshaler(r, visited)
}

func unmarshaler(r *lineReader, visited set.Set[any]) *json.Unmarshalers {
	return json.UnmarshalFromFunc(func(dec *jsontext.Decoder, loc ObjectLocation) error {
		// Decoder.InputOffset reports the offset after the last token,
		// but we want to record the offset before the next token.
		//
		// Call Decoder.PeekKind to buffer enough to reach the next token.
		// Add the number of leading whitespace, commas, and colons
		// to locate the start of the next token.
		// cf. https://pkg.go.dev/github.com/go-json-experiment/json@v0.0.0-20250223041408-d3c622f1b874#example-WithUnmarshalers-RecordOffsets
		kind := dec.PeekKind()

		unread := bytes.TrimLeft(dec.UnreadBuffer(), " \n\r\t,:")
		start := r.Line() - bytes.Count(unread, []byte("\n")) // The decoder buffer may have read more lines.

		// Check visited set to avoid infinity loops
		if visited.Contains(start) {
			return json.SkipFunc
		}
		visited.Append(start)

		// Return more detailed error for cases when UnmarshalJSONFrom is not implemented for primitive type.
		if _, ok := loc.(json.UnmarshalerFrom); !ok && kind != '[' && kind != '{' {
			return xerrors.Errorf("structures with single primitive type should implement UnmarshalJSONFrom: %T", loc)
		}

		if err := json.UnmarshalDecode(dec, loc, json.WithUnmarshalers(unmarshaler(r, visited))); err != nil {
			return err
		}
		loc.SetLocation(types.Location{
			StartLine: start,
			EndLine:   r.Line() - bytes.Count(dec.UnreadBuffer(), []byte("\n")),
		})
		return nil
	})
}
