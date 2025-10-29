package set_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/set"
)

func TestNewCaseInsensitive(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []string
		desc   string
	}{
		{
			name:   "empty set",
			values: []string{},
			want:   []string{},
			desc:   "should create empty set when no values provided",
		},
		{
			name:   "single value",
			values: []string{"Hello"},
			want:   []string{"Hello"},
			desc:   "should create set with single value",
		},
		{
			name:   "multiple values",
			values: []string{"Hello", "World", "Test"},
			want:   []string{"Hello", "World", "Test"},
			desc:   "should create set with multiple values",
		},
		{
			name:   "case insensitive duplicates",
			values: []string{"Hello", "HELLO", "hello", "HeLLo"},
			want:   []string{"Hello"},
			desc:   "should treat case variations as duplicates and preserve first occurrence",
		},
		{
			name:   "mixed case duplicates",
			values: []string{"Test", "TEST", "test", "World", "WORLD"},
			want:   []string{"Test", "World"},
			desc:   "should treat case variations as duplicates across multiple strings and preserve first occurrences",
		},
		{
			name:   "empty strings",
			values: []string{"", "test", ""},
			want:   []string{"", "test"},
			desc:   "should handle empty strings and treat duplicates correctly",
		},
		{
			name:   "unicode strings",
			values: []string{"こんにちは", "世界", "こんにちは"},
			want:   []string{"こんにちは", "世界"},
			desc:   "should handle unicode strings correctly",
		},
		{
			name:   "strings with spaces",
			values: []string{"Hello World", "hello world", "HELLO WORLD"},
			want:   []string{"Hello World"},
			desc:   "should handle strings with spaces case-insensitively and preserve original spacing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.NewCaseInsensitive(tt.values...)
			assert.ElementsMatch(t, tt.want, s.Items(), "unexpected set contents")
		})
	}
}

func TestCaseInsensitiveSet_Append(t *testing.T) {
	tests := []struct {
		name    string
		initial []string
		append  []string
		want    []string
	}{
		{
			name:    "append to empty set",
			initial: []string{},
			append:  []string{"Hello", "World"},
			want:    []string{"Hello", "World"},
		},
		{
			name:    "append case variations",
			initial: []string{"Hello"},
			append:  []string{"HELLO", "hello"},
			want:    []string{"Hello"},
		},
		{
			name:    "append new and existing",
			initial: []string{"Hello"},
			append:  []string{"HELLO", "World"},
			want:    []string{"Hello", "World"},
		},
		{
			name:    "append empty slice",
			initial: []string{"Hello"},
			append:  []string{},
			want:    []string{"Hello"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.NewCaseInsensitive(tt.initial...)
			got := s.Append(tt.append...)

			assert.Equal(t, len(tt.want), got, "unexpected returned size")
			assert.ElementsMatch(t, tt.want, s.Items(), "unexpected set contents")
		})
	}
}

func TestCaseInsensitiveSet_Contains(t *testing.T) {
	tests := []struct {
		name    string
		initial []string
		check   string
		want    bool
	}{
		{
			name:    "exact match",
			initial: []string{"Hello"},
			check:   "Hello",
			want:    true,
		},
		{
			name:    "lowercase match",
			initial: []string{"Hello"},
			check:   "hello",
			want:    true,
		},
		{
			name:    "uppercase match",
			initial: []string{"Hello"},
			check:   "HELLO",
			want:    true,
		},
		{
			name:    "mixed case match",
			initial: []string{"Hello"},
			check:   "HeLLo",
			want:    true,
		},
		{
			name:    "not found",
			initial: []string{"Hello"},
			check:   "World",
			want:    false,
		},
		{
			name:    "empty string exists",
			initial: []string{""},
			check:   "",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.NewCaseInsensitive(tt.initial...)
			got := s.Contains(tt.check)
			assert.Equal(t, tt.want, got, "unexpected contains result")
		})
	}
}

func TestCaseInsensitiveSet_Remove(t *testing.T) {
	tests := []struct {
		name     string
		initial  []string
		remove   string
		wantSize int
	}{
		{
			name:     "remove exact match",
			initial:  []string{"Hello", "World"},
			remove:   "Hello",
			wantSize: 1,
		},
		{
			name:     "remove with different case",
			initial:  []string{"Hello", "World"},
			remove:   "hello",
			wantSize: 1,
		},
		{
			name:     "remove uppercase",
			initial:  []string{"Hello", "World"},
			remove:   "WORLD",
			wantSize: 1,
		},
		{
			name:     "remove non-existing",
			initial:  []string{"Hello"},
			remove:   "World",
			wantSize: 1,
		},
		{
			name:     "remove from empty set",
			initial:  []string{},
			remove:   "Hello",
			wantSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.NewCaseInsensitive(tt.initial...)
			s.Remove(tt.remove)
			got := s.Size()
			assert.Equal(t, tt.wantSize, got, "unexpected set size after remove")
			assert.False(t, s.Contains(tt.remove), "set should not contain removed item")
		})
	}
}

func TestCaseInsensitiveSet_Clear(t *testing.T) {
	tests := []struct {
		name    string
		initial []string
	}{
		{
			name:    "clear non-empty set",
			initial: []string{"Hello", "World", "Test"},
		},
		{
			name:    "clear empty set",
			initial: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.NewCaseInsensitive(tt.initial...)
			s.Clear()

			assert.Zero(t, s.Size(), "set should be empty after clear")
			assert.Empty(t, s.Items(), "items should be empty after clear")
		})
	}
}

func TestCaseInsensitiveSet_Clone(t *testing.T) {
	t.Run("empty set", func(t *testing.T) {
		original := set.NewCaseInsensitive()
		cloned := original.Clone()

		assert.Equal(t, 0, cloned.Size(), "cloned set should be empty")

		// Verify independence
		original.Append("test")
		assert.False(t, cloned.Contains("test"), "cloned set should not be affected by original")
	})

	t.Run("non-empty set", func(t *testing.T) {
		original := set.NewCaseInsensitive("Hello", "World")
		cloned := original.Clone()

		assert.Equal(t, original.Size(), cloned.Size(), "sizes should match")
		assert.True(t, cloned.Contains("hello"), "should contain hello (case insensitive)")
		assert.True(t, cloned.Contains("WORLD"), "should contain world (case insensitive)")

		// Verify independence
		original.Append("new")
		assert.False(t, cloned.Contains("new"), "cloned set should not be affected by original")
		cloned.Append("another")
		assert.False(t, original.Contains("another"), "original set should not be affected by clone")
	})

	t.Run("preserves casing", func(t *testing.T) {
		original := set.NewCaseInsensitive("Hello", "WORLD")
		cloned := original.Clone()

		assert.ElementsMatch(t, original.Items(), cloned.Items(), "cloned set should preserve original casing")
	})
}

func TestCaseInsensitiveSet_Union(t *testing.T) {
	tests := []struct {
		name string
		set1 []string
		set2 []string
		want []string
	}{
		{
			name: "non-overlapping sets",
			set1: []string{"Hello", "World"},
			set2: []string{"Test", "Data"},
			want: []string{"Hello", "World", "Test", "Data"},
		},
		{
			name: "overlapping sets with same case",
			set1: []string{"Hello", "World"},
			set2: []string{"World", "Test"},
			want: []string{"Hello", "World", "Test"},
		},
		{
			name: "overlapping sets with different case",
			set1: []string{"Hello", "World"},
			set2: []string{"HELLO", "test"},
			want: []string{"Hello", "World", "test"},
		},
		{
			name: "union with empty set",
			set1: []string{"Hello"},
			set2: []string{},
			want: []string{"Hello"},
		},
		{
			name: "empty sets union",
			set1: []string{},
			set2: []string{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := set.NewCaseInsensitive(tt.set1...)
			s2 := set.NewCaseInsensitive(tt.set2...)

			result := s1.Union(s2)
			got := result.Items()

			assert.ElementsMatch(t, tt.want, got, "unexpected union result")
		})
	}
}

func TestCaseInsensitiveSet_Intersection(t *testing.T) {
	tests := []struct {
		name string
		set1 []string
		set2 []string
		want []string
	}{
		{
			name: "overlapping sets with same case",
			set1: []string{"Hello", "World", "Test"},
			set2: []string{"World", "Test", "Data"},
			want: []string{"World", "Test"},
		},
		{
			name: "overlapping sets with different case",
			set1: []string{"Hello", "World"},
			set2: []string{"hello", "WORLD"},
			want: []string{"Hello", "World"},
		},
		{
			name: "non-overlapping sets",
			set1: []string{"Hello"},
			set2: []string{"World"},
			want: []string{},
		},
		{
			name: "intersection with empty set",
			set1: []string{"Hello"},
			set2: []string{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := set.NewCaseInsensitive(tt.set1...)
			s2 := set.NewCaseInsensitive(tt.set2...)

			result := s1.Intersection(s2)
			got := result.Items()

			assert.ElementsMatch(t, tt.want, got, "unexpected intersection result")
		})
	}
}

func TestCaseInsensitiveSet_Difference(t *testing.T) {
	tests := []struct {
		name string
		set1 []string
		set2 []string
		want []string
	}{
		{
			name: "difference with same case",
			set1: []string{"Hello", "World", "Test"},
			set2: []string{"World", "Data"},
			want: []string{"Hello", "Test"},
		},
		{
			name: "difference with different case",
			set1: []string{"Hello", "World", "Test"},
			set2: []string{"hello", "WORLD"},
			want: []string{"Test"},
		},
		{
			name: "difference with non-overlapping set",
			set1: []string{"Hello", "World"},
			set2: []string{"Test", "Data"},
			want: []string{"Hello", "World"},
		},
		{
			name: "difference with empty set",
			set1: []string{"Hello", "World"},
			set2: []string{},
			want: []string{"Hello", "World"},
		},
		{
			name: "difference of empty set",
			set1: []string{},
			set2: []string{"Hello"},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := set.NewCaseInsensitive(tt.set1...)
			s2 := set.NewCaseInsensitive(tt.set2...)

			result := s1.Difference(s2)
			got := result.Items()

			assert.ElementsMatch(t, tt.want, got, "unexpected difference result")
		})
	}
}
