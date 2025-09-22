package parser

import (
	"testing"

	"github.com/samber/lo"
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
	require.NoError(t, decodeYAML([]byte(src), &task))

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

func TestResolvedTasks_GetModules(t *testing.T) {
	src := `
- name: s3 bucket present
  amazon.aws.s3_bucket:
    name: mybucket

- name: user absent
  ansible.builtin.user:
    name: old_user

- name: debug task
  ansible.builtin.debug:
    msg: "Hello"
`
	var tasks []*Task
	require.NoError(t, decodeYAML([]byte(src), &tasks))

	var resolved ResolvedTasks
	for _, t := range tasks {
		resolved = append(resolved, t.resolved(nil))
	}

	modules := resolved.GetModules("amazon.aws.s3_bucket", "ansible.builtin.user")
	var names []string
	for _, m := range modules {
		names = append(names, m.Name)
	}

	expected := []string{"amazon.aws.s3_bucket", "ansible.builtin.user"}
	assert.ElementsMatch(t, expected, names)
}

func TestResolvedTasks_FilterByState(t *testing.T) {
	src := `
- name: task1
  state: present
- name: task2
  state: absent
- name: task3
  state: present
- name: task4
  # no state
`
	var tasks []*Task
	require.NoError(t, decodeYAML([]byte(src), &tasks))

	var resolved ResolvedTasks
	for _, t := range tasks {
		resolved = append(resolved, t.resolved(nil))
	}
	filtered := resolved.FilterByState("absent")

	names := lo.Map(filtered, func(t *ResolvedTask, _ int) string { return t.Name })
	assert.ElementsMatch(t, []string{"task1", "task3", "task4"}, names)
}

func TestResolvedTask_GetFieldsByRange(t *testing.T) {
	src := `a: valueA
b: valueB
c: valueC
d: valueD
`

	var task *Task
	require.NoError(t, decodeYAML([]byte(src), &task))

	resolved := task.resolved(nil)
	r := Range{Start: 2, End: 3}

	fields := resolved.GetFieldsByRange(r)

	expected := `b: valueB
c: valueC
`

	marshaled, err := yaml.Marshal(fields)
	require.NoError(t, err)

	assert.Equal(t, expected, string(marshaled))
}
