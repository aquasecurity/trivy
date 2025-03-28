package json

import (
	"bytes"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ObjectLocation is required when you need to save Location for your struct.
type ObjectLocation interface {
	SetLocation(location ftypes.Location)
}

// StringLocation is required for string object (e.g. array of strings).
type StringLocation interface {
	ObjectLocation
	SetString(s string)
}

// UnmarshalerWithObjectLocation creates json.Unmarshaler for ObjectLocation to save location using SetLocation function
// It doesn't support Location detection for nested objects (e.g. Dependency -> map[string]Dependency).
func UnmarshalerWithObjectLocation(data []byte) *json.Unmarshalers {
	return json.UnmarshalFromFunc(func(dec *jsontext.Decoder, loc ObjectLocation, _ json.Options) error {
		value, err := dec.ReadValue()
		if err != nil {
			return err
		}

		// To determine line numbers for a string, we create a new struct with `StartLine` and `EndLine` fields.
		// but github.com/go-json-experiment/json can't unmarshal a string to a struct.
		// So for these cases, we need to unmarshal the value to a string and store the value using `StringLocation`
		if l, ok := loc.(StringLocation); ok {
			var s string
			if err = json.Unmarshal(value, &s); err != nil {
				return err
			}
			l.SetString(s)
			loc = l
		} else {
			if err = json.Unmarshal(value, &loc); err != nil {
				return err
			}
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
func CountLines(startOffset, endOffset int64, data []byte) ftypes.Location {
	return ftypes.Location{
		StartLine: 1 + bytes.Count(data[:startOffset], []byte("\n")),
		EndLine:   1 + bytes.Count(data[:endOffset], []byte("\n")),
	}
}
