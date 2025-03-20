package jsonutils

import (
	"bytes"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// CountLines calculates the number of lines in `data` and returns the start and end line.
// Used to calculate locations in functions in the "github.com/go-json-experiment/json" package.
func CountLines(offsetEnd int64, data, value []byte) ftypes.Location {
	offsetStart := offsetEnd - int64(len(value))
	return ftypes.Location{
		StartLine: 1 + bytes.Count(data[:offsetStart], []byte("\n")),
		EndLine:   1 + bytes.Count(data[:offsetEnd], []byte("\n")),
	}
}
