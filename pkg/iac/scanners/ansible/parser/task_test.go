package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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

	resolved := task.resolved(vars.Vars{
		"name": "test task",
		"msg":  "hello",
		"num":  42,
	})

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
