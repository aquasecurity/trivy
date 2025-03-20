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

// StringLocation is required when your struct has only string and Location
type StringLocation interface {
	ObjectLocation
	SetString(s string)
}

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

		loc.SetLocation(countLines(endOffset, data, value))
		return nil
	})

}

// countLines returns the Location for the unmarshaled object.
// "github.com/go-json-experiment/json" does not have a line number option,
// so we calculate the Location based on the ending offset and the length of the Object.
func countLines(offsetEnd int64, data, value []byte) ftypes.Location {
	// The dec.InputOffset() function returns previousOffsetEnd.
	// But there are cases when this value does not include line breaks.
	// TODO add link to example
	// So we need to calculate the starting line using the length of the value.
	offsetStart := offsetEnd - int64(len(value))
	return ftypes.Location{
		StartLine: 1 + bytes.Count(data[:offsetStart], []byte("\n")),
		EndLine:   1 + bytes.Count(data[:offsetEnd], []byte("\n")),
	}
}
