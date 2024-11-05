package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MetadataToRego(t *testing.T) {
	m1 := NewTestMetadata()
	m1.isUnresolvable = true
	expected := map[string]any{
		"endline":      123,
		"explicit":     false,
		"filepath":     "test.test",
		"fskey":        "",
		"managed":      true,
		"unresolvable": true,
		"resource":     "",
		"sourceprefix": "",
		"startline":    123,
	}
	assert.Equal(t, expected, m1.ToRego())
	m2 := NewTestMetadata()
	m1.SetParentPtr(&m2)
	expected["parent"] = map[string]any{
		"endline":      123,
		"explicit":     false,
		"filepath":     "test.test",
		"fskey":        "",
		"managed":      true,
		"unresolvable": false,
		"resource":     "",
		"sourceprefix": "",
		"startline":    123,
	}
	assert.Equal(t, expected, m1.ToRego())
}
