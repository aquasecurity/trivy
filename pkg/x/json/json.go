package json

import (
	"bytes"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

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

// UnmarshalerWithObjectLocation creates json.Unmarshaler for ObjectLocation to save object location into xjson.Location
// To use UnmarshalerWithObjectLocation for primitive types, you must implement the UnmarshalerFrom interface for those objects.
// cf. https://pkg.go.dev/github.com/go-json-experiment/json#UnmarshalerFrom
func UnmarshalerWithObjectLocation(data []byte) *json.Unmarshalers {
	visited := set.New[any]()
	return unmarshaler(data, visited)
}

func unmarshaler(data []byte, visited set.Set[any]) *json.Unmarshalers {
	return json.UnmarshalFromFunc(func(dec *jsontext.Decoder, loc ObjectLocation) error {
		inputOffset := dec.InputOffset()
		kind := dec.PeekKind()

		//dec.InputOffset() returns `It gives the location of the next byte immediately after the most recently returned token or value.`
		//So, we need to find the location of the first token of the current object.
		inputOffset += int64(bytes.IndexByte(data[inputOffset:], byte(kind)))

		// Check visited set to avoid infinity loops
		if visited.Contains(inputOffset) {
			return json.SkipFunc
		}
		visited.Append(inputOffset)

		// Return more detailed error for cases when UnmarshalJSONFrom is not implemented for primitive type.
		if _, ok := loc.(json.UnmarshalerFrom); !ok && kind != '[' && kind != '{' {
			return xerrors.Errorf("structures with single primitive type should implement UnmarshalJSONFrom: %T", loc)
		}

		if err := json.UnmarshalDecode(dec, loc, json.WithUnmarshalers(unmarshaler(data, visited))); err != nil {
			return err
		}
		loc.SetLocation(CountLines(inputOffset, dec.InputOffset(), data))
		return nil
	})
}

// CountLines returns the Location for the unmarshaled object.
// "github.com/go-json-experiment/json" does not have a line number option,
// so we calculate the Location based on the starting and ending offset and `data`.
func CountLines(startOffset, endOffset int64, data []byte) types.Location {
	return types.Location{
		StartLine: 1 + bytes.Count(data[:startOffset], []byte("\n")),
		EndLine:   1 + bytes.Count(data[:endOffset], []byte("\n")),
	}
}
