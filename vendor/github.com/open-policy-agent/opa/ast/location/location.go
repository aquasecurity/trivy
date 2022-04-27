// Package location defines locations in Rego source code.
package location

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
)

// Location records a position in source code
type Location struct {
	Text   []byte `json:"-"`    // The original text fragment from the source.
	File   string `json:"file"` // The name of the source file (which may be empty).
	Row    int    `json:"row"`  // The line in the source.
	Col    int    `json:"col"`  // The column in the row.
	Offset int    `json:"-"`    // The byte offset for the location in the source.
}

// NewLocation returns a new Location object.
func NewLocation(text []byte, file string, row int, col int) *Location {
	return &Location{Text: text, File: file, Row: row, Col: col}
}

// Equal checks if two locations are equal to each other.
func (loc *Location) Equal(other *Location) bool {
	return bytes.Equal(loc.Text, other.Text) &&
		loc.File == other.File &&
		loc.Row == other.Row &&
		loc.Col == other.Col
}

// Errorf returns a new error value with a message formatted to include the location
// info (e.g., line, column, filename, etc.)
func (loc *Location) Errorf(f string, a ...interface{}) error {
	return errors.New(loc.Format(f, a...))
}

// Wrapf returns a new error value that wraps an existing error with a message formatted
// to include the location info (e.g., line, column, filename, etc.)
func (loc *Location) Wrapf(err error, f string, a ...interface{}) error {
	return errors.Wrap(err, loc.Format(f, a...))
}

// Format returns a formatted string prefixed with the location information.
func (loc *Location) Format(f string, a ...interface{}) string {
	if len(loc.File) > 0 {
		f = fmt.Sprintf("%v:%v: %v", loc.File, loc.Row, f)
	} else {
		f = fmt.Sprintf("%v:%v: %v", loc.Row, loc.Col, f)
	}
	return fmt.Sprintf(f, a...)
}

func (loc *Location) String() string {
	if len(loc.File) > 0 {
		return fmt.Sprintf("%v:%v", loc.File, loc.Row)
	}
	if len(loc.Text) > 0 {
		return string(loc.Text)
	}
	return fmt.Sprintf("%v:%v", loc.Row, loc.Col)
}

// Compare returns -1, 0, or 1 to indicate if this loc is less than, equal to,
// or greater than the other. Comparison is performed on the file, row, and
// column of the Location (but not on the text.) Nil locations are greater than
// non-nil locations.
func (loc *Location) Compare(other *Location) int {
	if loc == nil && other == nil {
		return 0
	} else if loc == nil {
		return 1
	} else if other == nil {
		return -1
	} else if loc.File < other.File {
		return -1
	} else if loc.File > other.File {
		return 1
	} else if loc.Row < other.Row {
		return -1
	} else if loc.Row > other.Row {
		return 1
	} else if loc.Col < other.Col {
		return -1
	} else if loc.Col > other.Col {
		return 1
	}
	return 0
}
