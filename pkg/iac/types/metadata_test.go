package types

import (
	"encoding/json/v2"
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

const encodedParentMetadata = `{"range":{"filename":"parent.tf","startLine":1,"endLine":10,"sourcePrefix":"parent-prefix","fsKey":"parent-key","isLogicalSource":false},"ref":"module.parent","managed":false,"default":false,"explicit":true,"unresolvable":true,"parent":null}`

const encodedMetadata = `{"range":` + encodedRange + `,"ref":"aws_s3_bucket.example","managed":true,"default":false,"explicit":false,"unresolvable":true,"parent":` + encodedParentMetadata + `}`

// populatedMetadata returns metadata with a parent, where no two flags have the same pair of values.
func populatedMetadata() Metadata {
	parent := NewMetadata(newRange("parent.tf", 1, 10, "parent-prefix", "parent-key", nil, false), "module.parent")
	parent.isManaged = false
	parent.isExplicit = true
	parent.isUnresolvable = true

	m := NewMetadata(newRange("main.tf", 2, 4, "prefix", "fs-key", nil, true), "aws_s3_bucket.example")
	m.isUnresolvable = true
	m.parent = &parent
	return m
}

func Test_MetadataMarshalJSON(t *testing.T) {
	data, err := json.Marshal(populatedMetadata())
	require.NoError(t, err)
	assert.JSONEq(t, encodedMetadata, string(data))
}

func Test_MetadataUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Metadata
		wantErr string
	}{
		{
			name:  "all fields",
			input: encodedMetadata,
			want:  populatedMetadata(),
		},
		{
			name:  "null parent",
			input: `{"parent":null}`,
			want:  Metadata{},
		},
		{
			name:    "parent is not an object",
			input:   `{"parent":"x"}`,
			wantErr: `within "/parent"`,
		},
		{
			name:    "wrong-typed ref",
			input:   `{"ref":1}`,
			wantErr: `within "/ref"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Metadata
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
