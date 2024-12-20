package set_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/set"
)

func Test_New(t *testing.T) {
	tests := []struct {
		name     string
		values   []int
		wantSize int
		wantAll  bool
		desc     string
	}{
		{
			name:     "new empty set",
			values:   []int{},
			wantSize: 0,
			wantAll:  true,
			desc:     "should create empty set when no values provided",
		},
		{
			name:     "new set with single value",
			values:   []int{1},
			wantSize: 1,
			wantAll:  true,
			desc:     "should create set with single value",
		},
		{
			name: "new set with multiple values",
			values: []int{
				1,
				2,
				3,
			},
			wantSize: 3,
			wantAll:  true,
			desc:     "should create set with multiple values",
		},
		{
			name: "new set with duplicate values",
			values: []int{
				1,
				2,
				2,
				3,
				3,
				3,
			},
			wantSize: 3,
			wantAll:  true,
			desc:     "should create set with unique values only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.New(tt.values...)
			assert.Equal(t, tt.wantSize, s.Size(), "unexpected set size")
		})
	}
}

func Test_unsafeSet_Add(t *testing.T) {
	// Define custom type for struct test cases
	type custom struct {
		id   int
		name string
	}

	tests := []struct {
		name     string
		prepare  func(s set.Set[any])
		input    any
		wantSize int
	}{
		{
			name:     "add integer",
			prepare:  nil,
			input:    1,
			wantSize: 1,
		},
		{
			name: "add duplicate integer",
			prepare: func(s set.Set[any]) {
				s.Append(1)
			},
			input:    1,
			wantSize: 1,
		},
		{
			name:     "add string",
			prepare:  nil,
			input:    "test",
			wantSize: 1,
		},
		{
			name:     "add empty string",
			prepare:  nil,
			input:    "",
			wantSize: 1,
		},
		{
			name:    "add custom struct",
			prepare: nil,
			input: custom{
				id:   1,
				name: "test1",
			},
			wantSize: 1,
		},
		{
			name:     "add nil pointer",
			prepare:  nil,
			input:    (*int)(nil),
			wantSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.New[any]()
			if tt.prepare != nil {
				tt.prepare(s)
			}
			s.Append(tt.input)

			got := s.Size()
			assert.Equal(t, tt.wantSize, got, "unexpected set size")
			assert.True(t, s.Contains(tt.input), "unexpected contains result for value: %v", tt.input)
		})
	}
}

func Test_unsafeSet_Append(t *testing.T) {
	tests := []struct {
		name     string
		prepare  func(s set.Set[int])
		input    []int
		wantSize int
	}{
		{
			name:    "append to empty set",
			prepare: nil,
			input: []int{
				1,
				2,
				3,
			},
			wantSize: 3,
		},
		{
			name: "append with duplicates",
			prepare: func(s set.Set[int]) {
				s.Append(1)
			},
			input: []int{
				1,
				2,
				1,
				3,
				2,
			},
			wantSize: 3,
		},
		{
			name: "append empty slice",
			prepare: func(s set.Set[int]) {
				s.Append(1)
			},
			input:    []int{},
			wantSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.New[int]()
			if tt.prepare != nil {
				tt.prepare(s)
			}
			got := s.Append(tt.input...)

			assert.Equal(t, tt.wantSize, got, "unexpected returned size")
			assert.Equal(t, tt.wantSize, s.Size(), "unexpected actual size")

			for _, item := range tt.input {
				assert.True(t, s.Contains(item), "set should contain appended item: %v", item)
			}
		})
	}
}

func Test_unsafeSet_Remove(t *testing.T) {
	tests := []struct {
		name     string
		prepare  func(s set.Set[int])
		input    int
		wantSize int
	}{
		{
			name: "remove existing element",
			prepare: func(s set.Set[int]) {
				s.Append(1)
			},
			input:    1,
			wantSize: 0,
		},
		{
			name: "remove non-existing element",
			prepare: func(s set.Set[int]) {
				s.Append(1)
			},
			input:    2,
			wantSize: 1,
		},
		{
			name:     "remove from empty set",
			prepare:  nil,
			input:    1,
			wantSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.New[int]()
			if tt.prepare != nil {
				tt.prepare(s)
			}
			s.Remove(tt.input)

			got := s.Size()
			assert.Equal(t, tt.wantSize, got, "unexpected set size")
			assert.False(t, s.Contains(tt.input), "unexpected contains result for value: %v", tt.input)
		})
	}
}

func Test_unsafeSet_Clear(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(s set.Set[int])
	}{
		{
			name: "clear non-empty set",
			prepare: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
				s.Append(3)
			},
		},
		{
			name:    "clear empty set",
			prepare: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.New[int]()
			if tt.prepare != nil {
				tt.prepare(s)
			}
			s.Clear()

			got := s.Size()
			assert.Zero(t, got, "unexpected set size")
			assert.Empty(t, s.Items(), "items should be empty")
		})
	}
}

func Test_unsafeSet_Clone(t *testing.T) {
	t.Run("empty set", func(t *testing.T) {
		original := set.New[string]()
		cloned := original.Clone()

		assert.Equal(t, 0, cloned.Size(), "cloned set should be empty")

		// Verify independence
		original.Append("test")
		assert.False(t, cloned.Contains("test"), "cloned set should not be affected by original")
	})

	t.Run("basic types", func(t *testing.T) {
		original := set.New[any](1, "test", true)
		cloned := original.Clone()

		assert.Equal(t, original.Size(), cloned.Size(), "sizes should match")
		assert.True(t, cloned.Contains(1), "should contain integer")
		assert.True(t, cloned.Contains("test"), "should contain string")
		assert.True(t, cloned.Contains(true), "should contain boolean")

		// Verify independence
		original.Append("new")
		assert.False(t, cloned.Contains("new"), "cloned set should not be affected by original")
		cloned.Append("another")
		assert.False(t, original.Contains("another"), "original set should not be affected by clone")
	})

	// Test nil pointer
	t.Run("nil pointer", func(t *testing.T) {
		original := set.New[*int]()
		original.Append(nil)

		cloned := original.Clone()

		assert.Equal(t, original.Size(), cloned.Size(), "sizes should match")
		assert.True(t, cloned.Contains((*int)(nil)), "should contain nil pointer")
	})
}

func Test_unsafeSet_Items(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(s set.Set[int])
		want    []int
	}{
		{
			name: "get items from non-empty set",
			prepare: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
				s.Append(3)
			},
			want: []int{
				1,
				2,
				3,
			},
		},
		{
			name:    "get items from empty set",
			prepare: nil,
			want:    []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := set.New[int]()
			if tt.prepare != nil {
				tt.prepare(s)
			}
			got := s.Items()

			assert.ElementsMatch(t, tt.want, got, "unexpected items in set")
		})
	}
}

func Test_unsafeSet_Union(t *testing.T) {
	tests := []struct {
		name     string
		prepare1 func(s set.Set[int])
		prepare2 func(s set.Set[int])
		want     []int
	}{
		{
			name: "union of non-overlapping sets",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
			},
			prepare2: func(s set.Set[int]) {
				s.Append(3)
				s.Append(4)
			},
			want: []int{
				1,
				2,
				3,
				4,
			},
		},
		{
			name: "union of overlapping sets",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
				s.Append(3)
			},
			prepare2: func(s set.Set[int]) {
				s.Append(2)
				s.Append(3)
				s.Append(4)
			},
			want: []int{
				1,
				2,
				3,
				4,
			},
		},
		{
			name: "union with empty set",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
			},
			prepare2: nil,
			want: []int{
				1,
				2,
			},
		},
		{
			name:     "union of empty sets",
			prepare1: nil,
			prepare2: nil,
			want:     []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := set.New[int]()
			s2 := set.New[int]()

			if tt.prepare1 != nil {
				tt.prepare1(s1)
			}
			if tt.prepare2 != nil {
				tt.prepare2(s2)
			}

			result := s1.Union(s2)
			got := result.Items()

			assert.ElementsMatch(t, tt.want, got, "unexpected union result")
		})
	}
}

func Test_unsafeSet_Intersection(t *testing.T) {
	tests := []struct {
		name     string
		prepare1 func(s set.Set[int])
		prepare2 func(s set.Set[int])
		want     []int
	}{
		{
			name: "intersection of overlapping sets",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
				s.Append(3)
			},
			prepare2: func(s set.Set[int]) {
				s.Append(2)
				s.Append(3)
				s.Append(4)
			},
			want: []int{
				2,
				3,
			},
		},
		{
			name: "intersection of non-overlapping sets",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
			},
			prepare2: func(s set.Set[int]) {
				s.Append(3)
				s.Append(4)
			},
			want: []int{},
		},
		{
			name: "intersection with empty set",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
			},
			prepare2: nil,
			want:     []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := set.New[int]()
			s2 := set.New[int]()

			if tt.prepare1 != nil {
				tt.prepare1(s1)
			}
			if tt.prepare2 != nil {
				tt.prepare2(s2)
			}

			result := s1.Intersection(s2)
			got := result.Items()

			assert.ElementsMatch(t, tt.want, got, "unexpected intersection result")
		})
	}
}

func Test_unsafeSet_Difference(t *testing.T) {
	tests := []struct {
		name     string
		prepare1 func(s set.Set[int])
		prepare2 func(s set.Set[int])
		want     []int
	}{
		{
			name: "difference of overlapping sets",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
				s.Append(3)
			},
			prepare2: func(s set.Set[int]) {
				s.Append(2)
				s.Append(3)
				s.Append(4)
			},
			want: []int{1},
		},
		{
			name: "difference with non-overlapping set",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
			},
			prepare2: func(s set.Set[int]) {
				s.Append(3)
				s.Append(4)
			},
			want: []int{
				1,
				2,
			},
		},
		{
			name: "difference with empty set",
			prepare1: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
			},
			prepare2: nil,
			want: []int{
				1,
				2,
			},
		},
		{
			name:     "difference of empty set",
			prepare1: nil,
			prepare2: func(s set.Set[int]) {
				s.Append(1)
				s.Append(2)
			},
			want: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := set.New[int]()
			s2 := set.New[int]()
			if tt.prepare1 != nil {
				tt.prepare1(s1)
			}
			if tt.prepare2 != nil {
				tt.prepare2(s2)
			}

			result := s1.Difference(s2)
			got := result.Items()

			assert.ElementsMatch(t, tt.want, got, "unexpected difference result")
		})
	}
}
