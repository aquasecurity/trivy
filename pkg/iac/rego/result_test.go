package rego

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseResult(t *testing.T) {
	var testCases = []struct {
		name  string
		input interface{}
		want  regoResult
	}{
		{
			name:  "unknown",
			input: nil,
			want: regoResult{
				Managed: true,
				Message: "Rego policy resulted in DENY",
			},
		},
		{
			name:  "string",
			input: "message",
			want: regoResult{
				Managed: true,
				Message: "message",
			},
		},
		{
			name:  "strings",
			input: []interface{}{"message"},
			want: regoResult{
				Managed: true,
				Message: "message",
			},
		},
		{
			name: "maps",
			input: []interface{}{
				"message",
				map[string]interface{}{
					"filepath": "a.out",
				},
			},
			want: regoResult{
				Managed:  true,
				Message:  "message",
				Filepath: "a.out",
			},
		},
		{
			name: "map",
			input: map[string]interface{}{
				"msg":          "message",
				"filepath":     "a.out",
				"fskey":        "abcd",
				"resource":     "resource",
				"startline":    "123",
				"endline":      "456",
				"sourceprefix": "git",
				"explicit":     true,
				"managed":      true,
			},
			want: regoResult{
				Message:      "message",
				Filepath:     "a.out",
				Resource:     "resource",
				StartLine:    123,
				EndLine:      456,
				SourcePrefix: "git",
				FSKey:        "abcd",
				Explicit:     true,
				Managed:      true,
			},
		},
		{
			name: "parent",
			input: map[string]interface{}{
				"msg": "child",
				"parent": map[string]interface{}{
					"msg": "parent",
				},
			},
			want: regoResult{
				Message: "child",
				Managed: true,
				Parent: &regoResult{
					Message: "parent",
					Managed: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := parseResult(tc.input)
			assert.NotNil(t, have)
			assert.Equal(t, tc.want, *have)
		})
	}
}
