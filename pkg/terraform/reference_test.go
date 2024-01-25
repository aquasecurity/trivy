package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func Test_ReferenceParsing(t *testing.T) {
	cases := []struct {
		input    []string
		expected string
	}{
		{
			input:    []string{"module", "my-mod"},
			expected: "module.my-mod",
		},
		{
			input:    []string{"aws_s3_bucket", "test"},
			expected: "aws_s3_bucket.test",
		},
		{
			input:    []string{"resource", "aws_s3_bucket", "test"},
			expected: "aws_s3_bucket.test",
		},
		{
			input:    []string{"module", "my-mod"},
			expected: "module.my-mod",
		},
		{
			input:    []string{"data", "aws_iam_policy_document", "s3_policy"},
			expected: "data.aws_iam_policy_document.s3_policy",
		},
		{
			input:    []string{"provider", "aws"},
			expected: "provider.aws",
		},
		{
			input:    []string{"output", "something"},
			expected: "output.something",
		},
	}

	for _, test := range cases {
		t.Run(test.expected, func(t *testing.T) {
			ref, err := newReference(test.input, "")
			assert.NoError(t, err)
			assert.Equal(t, test.expected, ref.String())
		})
	}
}

func Test_SetKey(t *testing.T) {
	tests := []struct {
		name string
		key  cty.Value
		want cty.Value
	}{
		{
			name: "happy",
			key:  cty.StringVal("str"),
			want: cty.StringVal("str"),
		},
		{
			name: "null key",
			key:  cty.NullVal(cty.String),
			want: cty.Value{},
		},
		{
			name: "unknown key",
			key:  cty.UnknownVal(cty.String),
			want: cty.Value{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run(tt.name, func(t *testing.T) {
				ref, err := newReference([]string{"resource", "test"}, "")
				require.NoError(t, err)

				ref.SetKey(tt.key)

				assert.Equal(t, tt.want, ref.RawKey())
			})
		})
	}
}

func Test_Key(t *testing.T) {

	tests := []struct {
		name string
		key  cty.Value
		want string
	}{
		{
			name: "empty key",
			want: "",
		},
		{
			name: "str key",
			key:  cty.StringVal("some_value"),
			want: "some_value",
		},
		{
			name: "number key",
			key:  cty.NumberIntVal(122),
			want: "122",
		},
		{
			name: "bool key",
			key:  cty.BoolVal(true),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run(tt.name, func(t *testing.T) {
				ref, err := newReference([]string{"resource", "test"}, "")
				require.NoError(t, err)

				ref.SetKey(tt.key)

				assert.Equal(t, tt.want, ref.Key())
			})
		})
	}
}

func Test_KeyBracketed(t *testing.T) {
	tests := []struct {
		name string
		key  cty.Value
		want string
	}{
		{
			name: "empty key",
			want: "",
		},
		{
			name: "str key",
			key:  cty.StringVal("some_value"),
			want: "[\"some_value\"]",
		},
		{
			name: "number key",
			key:  cty.NumberIntVal(122),
			want: "[122]",
		},
		{
			name: "bool key",
			key:  cty.BoolVal(true),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := newReference([]string{"resource", "test"}, "")
			require.NoError(t, err)

			ref.SetKey(tt.key)

			assert.Equal(t, tt.want, ref.KeyBracketed())
		})
	}
}
