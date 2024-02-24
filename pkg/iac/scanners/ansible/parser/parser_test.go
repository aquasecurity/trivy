package parser

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProject(t *testing.T) {
	fsys := os.DirFS(filepath.Join("testdata", "sample-proj"))

	project, err := New(fsys, ".").Parse()
	require.NoError(t, err)

	tasks := project.ListTasks()
	assert.Len(t, tasks, 6)
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name          string
		fsys          fs.FS
		expectedTasks []string
	}{
		{
			name: "tasks in play",
			fsys: fstest.MapFS{
				"playbook.yaml": {
					Data: []byte(`---
- hosts: localhost
  pre_tasks:
    - name: Pre-task
      debug:
        msg: test
  tasks:
    - name: Task
      debug:
        msg: test
  post_tasks:
    - name: Post-task
      debug:
        msg: test
`),
				},
			},
			expectedTasks: []string{"Pre-task", "Task", "Post-task"},
		},
		{
			name: "tasks in role",
			fsys: fstest.MapFS{
				"playbook.yaml": {
					Data: []byte(`---
- hosts: localhost
  roles:
    - test
`),
				},
				"roles/test/tasks/main.yaml": {
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "role with dependencies",
			fsys: fstest.MapFS{
				"playbook.yaml": {
					Data: []byte(`---
- hosts: localhost
  roles:
    - test
`),
				},
				"roles/test/tasks/main.yaml": {
					Data: []byte(`---
- name: Role task
  debug:
    msg: Test task
`),
				},
				"roles/test/meta/main.yaml": {
					Data: []byte(`---
dependencies:
  - role: role2
`),
				},
				"roles/role2/tasks/main.yaml": {
					Data: []byte(`---
- name: Dependent task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Dependent task", "Role task"},
		},
		{
			name: "block task",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- tasks:
    - name: Test block
      block:
        - name: Test task 1
          debug:
            msg: Test task
        - name: Test task 2
          debug:
            msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task 1", "Test task 2"},
		},
		{
			name: "include and import tasks in play",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  tasks:
    - name: Test task
      debug:
        msg: Test task

    - name: Include task list in play
      ansible.builtin.include_tasks:
        file: test.yaml

    - name: Import task list in play
      ansible.builtin.import_tasks:
        file: test2.yaml
`),
				},
				"test.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Included task
  debug:
    msg: Included task
`),
				},
				"test2.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Imported task
  debug:
    msg: Imported task
`),
				},
			},
			expectedTasks: []string{"Test task", "Included task", "Imported task"},
		},
		{
			name: "include and import tasks in role",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Update web servers
  hosts: localhost
  roles:
    - test
`),
				},
				"roles/test/tasks/main.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task

- name: Include task list in role
  ansible.builtin.include_tasks:
    file: test.yaml

- name: Import task list in role
  ansible.builtin.import_tasks:
    file: test2.yaml
`),
				},
				"roles/test/tasks/test.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Included task
  debug:
    msg: Included task
`),
				},
				"roles/test/tasks/test2.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Imported task
  debug:
    msg: Imported task
`),
				},
			},
			expectedTasks: []string{"Test task", "Included task", "Imported task"},
		},
		{
			name: "include role in play",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  tasks:
    - name: Test task
      include_role:
        name: test
        tasks_from: test
`),
				},
				"roles/test/tasks/main.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Main task
  debug:
    msg: Main task
`),
				},
				"roles/test/tasks/test.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "import role in play",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  tasks:
    - name: Test task
      import_role:
        name: test
        tasks_from: test
`),
				},
				"roles/test/tasks/main.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Main task
  debug:
    msg: Main task
`),
				},
				"roles/test/tasks/test.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include role in role",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  roles:
    - main
`),
				},
				"roles/main/tasks/main.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Main task
  include_role:
    name: test
    tasks_from: test
`),
				},
				"roles/test/tasks/test.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "import role in role",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  roles:
    - main
`),
				},
				"roles/main/tasks/main.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Main task
  ansible.builtin.import_role:
    name: test
    tasks_from: test
`),
				},
				"roles/test/tasks/test.yaml": &fstest.MapFile{
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include tasks is free form",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  tasks:
    - include_tasks: playbooks/test.yml
`),
				},
				"playbooks/test.yml": {
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "import playbook",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: localhost
  tasks:
    - name: Task
      debug:
        msg: test

- name: Include playbook
  ansible.builtin.import_playbook: other.yaml
`),
				},
				"other.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: localhost
  tasks:
    - name: Included Task
      debug:
        msg: test
`),
				},
			},
			expectedTasks: []string{"Task", "Included Task"},
		},
		{
			name: "with unused role",
			fsys: fstest.MapFS{
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: localhost
  roles: 
    - main
`),
				},
				"roles/main/tasks/main.yaml": {
					Data: []byte(`---
- name: Main role task
  debug:
    msg: test
`),
				},
				"roles/unused/tasks/main.yaml": {
					Data: []byte(`---
- name: Unused task
  debug:
    msg: test
`),
				},
			},
			expectedTasks: []string{"Main role task"},
		},
		{
			name: "with main playbook",
			fsys: fstest.MapFS{
				"site.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  tasks:
    - name: Task
      debug:
        msg: Test
`),
				},
				"playbook.yaml": &fstest.MapFile{
					Data: []byte(`---
- hosts: all
  tasks:
    - name: Unused task
      debug:
        msg: Test
`),
				},
			},
			expectedTasks: []string{"Task"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project, err := New(tt.fsys, ".").Parse()
			require.NoError(t, err)

			tasks := project.ListTasks()

			taskNames := lo.Map(tasks, func(task *Task, _ int) string {
				return task.name()
			})

			for _, task := range tasks {
				occ := task.occurrences()
				println(occ)
				_ = occ
			}

			assert.Equal(t, tt.expectedTasks, taskNames)
		})
	}
}
