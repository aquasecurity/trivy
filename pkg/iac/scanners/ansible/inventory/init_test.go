package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveComment(t *testing.T) {
	tests := []struct {
		in       string
		expected string
	}{
		{"foo # bar", "foo"},
		{"foo ; bar", "foo"},
		{`foo "# not comment" bar`, `foo "# not comment" bar`},
		{"foo", "foo"},
		{"   foo   ", "foo"},
		{"", ""},
	}

	for _, tt := range tests {
		got := removeComment(tt.in)
		assert.Equal(t, tt.expected, got)
	}
}

func TestSplitFields(t *testing.T) {
	tests := []struct {
		in       string
		expected []string
	}{
		{"foo bar baz", []string{"foo", "bar", "baz"}},
		{"foo   bar\tbaz", []string{"foo", "bar", "baz"}},
		{`foo "bar baz" qux`, []string{"foo", "bar baz", "qux"}},
		{`foo 'bar baz'`, []string{"foo", "bar baz"}},
		{`foo bar\ baz`, []string{"foo", "bar baz"}},
		{`"foo"`, []string{"foo"}},
		{"", []string{}},
	}

	for _, tt := range tests {
		got := splitFields(tt.in)
		assert.ElementsMatch(t, tt.expected, got)
	}
}
