package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

const encodedParentMetadata = `{"range":{"filename":"parent.tf","startLine":1,"endLine":10,"sourcePrefix":"parent-prefix","fsKey":"parent-key","isLogicalSource":false},"ref":"module.parent","managed":true,"default":false,"explicit":false,"unresolvable":false,"parent":null}`

const encodedMetadata = `{"range":` + encodedRange + `,"ref":"aws_s3_bucket.example","managed":true,"default":true,"explicit":true,"unresolvable":true,"parent":` + encodedParentMetadata + `}`

// populatedMetadata returns metadata with every serialized field set to a non-zero value.
func populatedMetadata() Metadata {
	parent := NewMetadata(newRange("parent.tf", 1, 10, "parent-prefix", "parent-key", nil, false), "module.parent")

	m := NewMetadata(newRange("main.tf", 2, 4, "prefix", "fs-key", nil, true), "aws_s3_bucket.example")
	m.isDefault = true
	m.isExplicit = true
	m.isUnresolvable = true
	m.parent = &parent
	return m
}

func Test_MetadataJSON(t *testing.T) {
	m := populatedMetadata()

	t.Run("marshal", func(t *testing.T) {
		data, err := json.Marshal(m)
		require.NoError(t, err)
		assert.JSONEq(t, encodedMetadata, string(data))
	})

	t.Run("unmarshal", func(t *testing.T) {
		var restored Metadata
		require.NoError(t, json.Unmarshal([]byte(encodedMetadata), &restored))
		assert.Equal(t, m, restored)
	})
}
