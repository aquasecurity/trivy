// Copied from github.com/hashicorp/terraform/internal/lang/marks
package funcs

import (
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// valueMarks allow creating strictly typed values for use as cty.Value marks.
// The variable name for new values should be the title-cased format of the
// value to better match the GoString output for debugging.
type valueMark string

func (m valueMark) GoString() string {
	return "marks." + cases.Title(language.English).String(string(m))
}

// Has returns true if and only if the cty.Value has the given mark.
func Has(val cty.Value, mark valueMark) bool {
	return val.HasMark(mark)
}

// Contains returns true if the cty.Value or any any value within it contains
// the given mark.
func Contains(val cty.Value, mark valueMark) bool {
	ret := false
	_ = cty.Walk(val, func(_ cty.Path, v cty.Value) (bool, error) {
		if v.HasMark(mark) {
			ret = true
			return false, nil
		}
		return true, nil
	})
	return ret
}

// MarkedSensitive indicates that this value is marked as sensitive in the context of
// Terraform.
const MarkedSensitive = valueMark("sensitive")

// MarkedRaw is used to indicate to the repl that the value should be written without
// any formatting.
const MarkedRaw = valueMark("raw")
