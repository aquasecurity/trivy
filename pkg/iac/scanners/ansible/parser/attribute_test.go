package parser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAttribute_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected Attribute
	}{
		{
			name: "happy",
			src: `name: testname
len: 100
keys:
  - a
  - 101
  - true
state:
  name: test
  len: 200 
`,
			expected: Attribute{
				rng: Range{0, 9},
				inner: attributeInner{
					kind: Map,
					val: map[string]*Attribute{
						"name": {
							rng: Range{1, 1},
							inner: attributeInner{
								kind: String,
								val:  "testname",
							},
						},
						"len": {
							rng: Range{2, 2},
							inner: attributeInner{
								kind: Int,
								val:  100,
							},
						},
						"keys": {
							rng: Range{3, 6}, // TODO: startLine == 3?
							inner: attributeInner{
								kind: List,
								val: []*Attribute{
									{
										rng: Range{4, 4},
										inner: attributeInner{
											kind: String,
											val:  "a",
										},
									},
									{
										rng: Range{5, 5},
										inner: attributeInner{
											kind: Int,
											val:  101,
										},
									},
									{
										rng: Range{6, 6},
										inner: attributeInner{
											kind: Bool,
											val:  true,
										},
									},
								},
							},
						},
						"state": {
							rng: Range{7, 9}, // TODO: startLine == 7?
							inner: attributeInner{
								kind: Map,
								val: map[string]*Attribute{
									"name": {
										rng: Range{8, 8},
										inner: attributeInner{
											kind: String,
											val:  "test",
										},
									},
									"len": {
										rng: Range{9, 9},
										inner: attributeInner{
											kind: Int,
											val:  200,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attr Attribute
			err := yaml.Unmarshal([]byte(tt.src), &attr)
			require.NoError(t, err)

			diff := cmp.Diff(tt.expected, attr, cmp.AllowUnexported(Attribute{}, attributeInner{}, Range{}), cmpopts.IgnoreFields(Attribute{}, "metadata"))

			if diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestAttribute_GetNestedAttr(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		path     string
		expected any
	}{
		{
			name: "happy",
			src: `
tags:
  example: tag1`,
			path:     "tags.example",
			expected: "tag1",
		},
		{
			name:     "first level",
			src:      `name: mys3bucket`,
			path:     "name",
			expected: "mys3bucket",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attr Attribute
			err := yaml.Unmarshal([]byte(tt.src), &attr)
			require.NoError(t, err)

			got := attr.GetNestedAttr(tt.path).Value()
			assert.Equal(t, tt.expected, got)
		})
	}
}
