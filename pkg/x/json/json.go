package json

import (
	"bytes"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

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

// UnmarshalerWithObjectLocation creates json.Unmarshaler for ObjectLocation to save location using SetLocation function
// It doesn't support Location detection for nested objects (e.g. Dependency -> map[string]Dependency).
//
// UnmarshalerWithObjectLocation may return an error for primitive types,
// so you need to implement the UnmarshalerFrom interface for these objects
// cf. https://pkg.go.dev/github.com/go-json-experiment/json#UnmarshalerFrom
func UnmarshalerWithObjectLocation(data []byte) *json.Unmarshalers {
	return json.UnmarshalFromFunc(func(dec *jsontext.Decoder, loc ObjectLocation) error {
		value, err := dec.ReadValue()
		if err != nil {
			return err
		}

		if err = json.Unmarshal(value, &loc); err != nil {
			return err
		}
		endOffset := dec.InputOffset()
		// The dec.InputOffset() function returns previousOffsetEnd.
		// But there are cases when this value doesn't include line breaks (e.g. for array of strings).
		// See "Location for only string" test for more details.
		// So we need to calculate the starting line using the length of the value.
		startOffset := endOffset - int64(len(value))

		loc.SetLocation(CountLines(startOffset, endOffset, data))
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
