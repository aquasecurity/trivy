package json

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// lineReader is a custom reader that tracks line numbers.
type lineReader struct {
	r    io.Reader
	line int
}

// NewLineReader creates a new line reader.
func NewLineReader(r io.Reader) *lineReader {
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
	lr := NewLineReader(r)
	unmarshalers := UnmarshalerWithLocation[ObjectLocation](lr)
	return json.UnmarshalRead(lr, v, json.WithUnmarshalers(unmarshalers))
}

// Location is wrap of types.Location.
// This struct is required when you need to detect location of your object from json file.
type Location types.Location

func (l *Location) SetLocation(location types.Location) {
	*l = Location(location)
}

// ObjectLocation is required when you need to save Location for your struct.
type ObjectLocation interface {
	SetLocation(location types.Location)
}

type DecodeHook struct {
	After func(dec *jsontext.Decoder, target any, loc types.Location)
}

var SetLocationHook = DecodeHook{
	After: func(_ *jsontext.Decoder, target any, location types.Location) {
		if loc, ok := target.(ObjectLocation); ok {
			loc.SetLocation(location)
		}
	},
}

// UnmarshalerWithLocation returns a [json.Unmarshalers] that captures the source code location
// (start and end lines) of each decoded object and optionally invokes hooks after decoding.
//
// By default, the [SetLocationHook] is used to record source code locations,
// unless other hooks are explicitly provided.
//
// To use UnmarshalerWithLocation for primitive types, you must implement the [json.UnmarshalerFrom] interface for those objects.
// cf. https://pkg.go.dev/github.com/go-json-experiment/json#UnmarshalerFrom
func UnmarshalerWithLocation[T any](r *lineReader, hooks ...DecodeHook) *json.Unmarshalers {
	if len(hooks) == 0 {
		hooks = []DecodeHook{SetLocationHook}
	}
	l := &locator{
		r:     r,
		hooks: hooks,
	}
	return json.UnmarshalFromFunc(l.unmarshal[T])
}

// locator records the location of each decoded value.
// One locator serves the whole document, so that json/v2 reuses the type lookups it has cached.
type locator struct {
	r     *lineReader
	hooks []DecodeHook
	skip  bool
}

func (l *locator) unmarshal[T any](dec *jsontext.Decoder, target T) error {
	// json.UnmarshalDecode below passes the same value to this method again.
	// ErrUnsupported leaves that repeated call to the default decoding and breaks the recursion.
	if l.skip {
		l.skip = false
		return errors.ErrUnsupported
	}

	// Decoder.InputOffset reports the offset after the last token,
	// but we want to record the offset before the next token.
	//
	// Call Decoder.PeekKind to buffer enough to reach the next token.
	// Add the number of leading whitespace, commas, and colons
	// to locate the start of the next token.
	// cf. https://pkg.go.dev/github.com/go-json-experiment/json@v0.0.0-20250223041408-d3c622f1b874#example-WithUnmarshalers-RecordOffsets
	kind := dec.PeekKind()

	unread := bytes.TrimLeft(dec.UnreadBuffer(), " \n\r\t,:")
	start := l.r.Line() - bytes.Count(unread, []byte("\n")) // The decoder buffer may have read more lines.

	// Return more detailed error for cases when UnmarshalJSONFrom is not implemented for primitive type.
	if _, ok := any(target).(json.UnmarshalerFrom); !ok && kind != jsontext.KindBeginArray && kind != jsontext.KindBeginObject {
		return xerrors.Errorf("structures with single primitive type should implement UnmarshalJSONFrom: %T", target)
	}

	// The decoder carries this locator in its options, so nested values are intercepted
	// without passing the unmarshalers again.
	l.skip = true
	if err := json.UnmarshalDecode(dec, target); err != nil {
		return err
	}

	location := types.Location{
		StartLine: start,
		EndLine:   l.r.Line() - bytes.Count(dec.UnreadBuffer(), []byte("\n")),
	}

	for _, h := range l.hooks {
		if h.After != nil {
			h.After(dec, target, location)
		}
	}

	return nil
}
