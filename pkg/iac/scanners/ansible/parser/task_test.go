package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func TestResolvedTask_MarshalYAML(t *testing.T) {
	src := `name: "{{ name }}"
msg: "{{ msg }}"
num: "{{ num }}"
nested:
  foo: "foo"
`

	var task Task
	require.NoError(t, yaml.Unmarshal([]byte(src), &task))

	plainVars := vars.PlainVars{
		"name": "test task",
		"msg":  "hello",
		"num":  42,
	}
	resolved := task.resolved(vars.NewVars(plainVars, 0))

	data, err := yaml.Marshal(resolved)
	require.NoError(t, err)

	got := string(data)
	wantSubstrs := []string{
		"name: test task",
		"msg: hello",
		`num: "42"`,
		`foo: foo`,
	}
	for _, substr := range wantSubstrs {
		assert.Contains(t, got, substr)
	}
}

func TestResolvedTask_GetFieldsByRange(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		query    Range
		expected []string
	}{
		{
			name: "single top-level field",
			src: `name: test
len: 100
state:
  foo: bar
  num: 42
`,
			query:    Range{1, 1},
			expected: []string{"name"},
		},
		{
			name: "single nested field",
			src: `name: test
len: 100
state:
  foo: bar
  num: 42
`,
			query:    Range{4, 4},
			expected: []string{"state.foo"},
		},
		{
			name: "nested mapping",
			src: `name: test
len: 100
state:
  foo: bar
  num: 42
`,
			query:    Range{4, 5},
			expected: []string{"state.foo", "state.num"},
		},
		{
			name: "full task",
			src: `name: test
len: 100
state:
  foo: bar
  num: 42
`,
			query:    Range{1, 5},
			expected: []string{"name", "len", "state"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var task Task
			err := yaml.Unmarshal([]byte(tt.src), &task)
			require.NoError(t, err)

			resolvedTask := task.resolved(make(vars.Vars))
			got := resolvedTask.GetFieldsByRange(tt.query)

			gotKeys := make([]string, 0, len(got))
			for k := range got {
				gotKeys = append(gotKeys, k)
			}

			assert.ElementsMatch(t, tt.expected, gotKeys)
		})
	}
}
