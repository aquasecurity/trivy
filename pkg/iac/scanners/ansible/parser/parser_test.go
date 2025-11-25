package parser_test

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
)

func TestParseProject(t *testing.T) {
	fsys := os.DirFS(filepath.Join("testdata", "sample-proj"))

	project, err := parser.New(fsys, ".").Parse()
	require.NoError(t, err)

	tasks := project.ListTasks()
	assert.Len(t, tasks, 6)
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name          string
		dir           string
		opts          []parser.Option
		files         map[string]string
		expectedTasks []string
	}{
		{
			name: "tasks in play",
			files: map[string]string{
				"playbook.yaml": `---
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
`,
			},
			expectedTasks: []string{"Pre-task", "Task", "Post-task"},
		},
		{
			name: "task name with unquoted template",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: localhost
  tasks:
    - name: {{ Task }}
      debug:
        msg: test
`,
			},
			expectedTasks: []string{"{{ Task }}"},
		},
		{
			name: "tasks in role",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: localhost
  roles:
    - test
`,
				"roles/test/tasks/main.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "role with dependencies",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: localhost
  roles:
    - test
`,
				"roles/test/tasks/main.yaml": `---
- name: Role task
  debug:
    msg: Test task
`,
				"roles/test/meta/main.yaml": `---
dependencies:
  - role: role2
`,
				"roles/role2/tasks/main.yaml": `---
- name: Dependent task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Dependent task", "Role task"},
		},
		{
			name: "block task",
			files: map[string]string{
				"playbook.yaml": `---
- tasks:
    - name: Test block
      block:
        - name: Test task 1
          debug:
            msg: Test task
        - name: Test task 2
          debug:
            msg: Test task
`,
			},
			expectedTasks: []string{"Test task 1", "Test task 2"},
		},
		{
			name: "block task includes role",
			files: map[string]string{
				"playbook.yaml": `---
- tasks:
    - name: Test block
      block:
        - name: Test task
          include_role:
            name: test
`,
				"roles/test/tasks/main.yaml": `---
- name: Role task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Role task"},
		},
		{
			name: "nested block includes tasks",
			dir:  "playbooks",
			files: map[string]string{
				"playbooks/playbook.yaml": `---
- tasks:
    - name: Test block
      block:
        - name: nested block
          block:
            - include_tasks:
                file: test.yaml
`,
				"playbooks/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include and import tasks in play",
			files: map[string]string{
				"playbook.yaml": `---
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
`,
				"test.yaml": `---
- name: Included task
  debug:
    msg: Included task
`,
				"test2.yaml": `---
- name: Imported task
  debug:
    msg: Imported task
`,
			},
			expectedTasks: []string{"Test task", "Included task", "Imported task"},
		},
		{
			name: "unresolved template in include",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  tasks:
    - name: Test task
      debug:
        msg: Test task

    - include_tasks: "{{item}}"
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include and import tasks in role",
			files: map[string]string{
				"playbook.yaml": `---
- name: Update web servers
  hosts: localhost
  roles:
    - test
`,
				"roles/test/tasks/main.yaml": `---
- name: Test task
  debug:
    msg: Test task

- name: Include task list in role
  ansible.builtin.include_tasks:
    file: test.yaml

- name: Import task list in role
  ansible.builtin.import_tasks:
    file: test2.yaml
`,
				"roles/test/tasks/test.yaml": `---
- name: Included task
  debug:
    msg: Included task
`,
				"roles/test/tasks/test2.yaml": `---
- name: Imported task
  debug:
    msg: Imported task
`,
			},
			expectedTasks: []string{"Test task", "Included task", "Imported task"},
		},
		{
			name: "include role in play",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  tasks:
    - name: Test task
      include_role:
        name: test
        tasks_from: test
`,
				"roles/test/tasks/main.yaml": `---
- name: Main task
  debug:
    msg: Main task
`,
				"roles/test/tasks/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "inline include role in play",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  tasks:
    - {include_role: {name: test, tasks_from: test}}
`,
				"roles/test/tasks/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include role in play by path",
			dir:  "playbooks",
			files: map[string]string{
				"playbooks/playbook.yaml": `---
- hosts: all
  tasks:
    - {include_role: {name: ../roles/test, tasks_from: test}}
`,
				"roles/test/tasks/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "role task from subdir",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  tasks:
    - {include_role: {name: test, tasks_from: subdir/test.yaml}}
`,
				"roles/test/tasks/subdir/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "import role in play",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  tasks:
    - name: Test task
      import_role:
        name: test
        tasks_from: test
`,
				"roles/test/tasks/main.yaml": `---
- name: Main task
  debug:
    msg: Main task
`,
				"roles/test/tasks/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include role in role",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  roles:
    - main
`,
				"roles/main/tasks/main.yaml": `---
- name: Main task
  include_role:
    name: test
    tasks_from: test
`,
				"roles/test/tasks/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "import role in role",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  roles:
    - main
`,
				"roles/main/tasks/main.yaml": `---
- name: Main task
  ansible.builtin.import_role:
    name: test
    tasks_from: test
`,
				"roles/test/tasks/test.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include tasks is free form",
			dir:  "playbooks",
			files: map[string]string{
				"playbooks/playbook.yaml": `---
- hosts: all
  tasks:
    - include_tasks: "{{ playbook_dir |dirname }}/tasks/test.yml"
`,
				"playbooks/tasks/test.yml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "include_tasks with templated path",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: all
  tasks:
    - include_tasks: "{{ tasks_file }}"
      vars:
        tasks_file: tasks/test.yml
`,
				"tasks/test.yml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "import playbook",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: localhost
  tasks:
    - name: Task
      debug:
        msg: test

- name: Include playbook
  ansible.builtin.import_playbook: other.yaml
`,
				"other.yaml": `---
- hosts: localhost
  tasks:
    - name: Included Task
      debug:
        msg: test
`,
			},
			expectedTasks: []string{"Task", "Included Task"},
		},
		{
			name: "with unused role",
			files: map[string]string{
				"playbook.yaml": `---
- hosts: localhost
  roles: 
    - main
`,
				"roles/main/tasks/main.yaml": `---
- name: Main role task
  debug:
    msg: test
`,
				"roles/unused/tasks/main.yaml": `---
- name: Unused task
  debug:
    msg: test
`,
			},
			expectedTasks: []string{"Main role task"},
		},
		{
			name: "multiple playbooks",
			files: map[string]string{
				"site.yaml": `---
- hosts: all
  tasks:
    - name: Foo task
      debug:
        msg: Test
`,
				"playbook.yaml": `---
- hosts: all
  tasks:
    - name: Bar task
      debug:
        msg: Test
`,
			},
			expectedTasks: []string{"Foo task", "Bar task"},
		},
		{
			name: "included playbook outside root directory",
			dir:  "project",
			files: map[string]string{
				"project/main.yml": `
- name: Main play
  hosts: all
  import_playbook: ../common/common.yml
`,
				"common/common.yml": `
- name: Common play
  hosts: all
  tasks:
    - name: task from common playbook
      debug: null
      msg: hello from common
`,
			},
			expectedTasks: []string{
				"task from common playbook",
			},
		},
		{
			name: "role from namespace.collection",
			dir:  "project",
			files: map[string]string{
				"project/galaxy.yaml": `
namespace: myns
name: mycol
`,
				"project/playbook.yml": `
- name: Play with collection role
  hosts: all
  roles:
    - myns.mycol.myrole
`,
				"project/roles/myrole/tasks/main.yml": `
- name: task from collection role
  debug:
    msg: hello from collection role
`,
			},
			expectedTasks: []string{
				"task from collection role",
			},
		},
		{
			name: "with playbook sources",
			dir:  "project",
			opts: []parser.Option{parser.WithPlaybooks("playbooks/playbook.yaml")},
			files: map[string]string{
				"project/playbooks/playbook.yaml": `---
- hosts: localhost
  roles:
    - "../roles/test"
`,
				"project/roles/test/tasks/main.yaml": `---
- name: Test task
  debug:
    msg: Test task
`,
			},
			expectedTasks: []string{"Test task"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(tt.files)
			dir := cmp.Or(tt.dir, ".")
			p := parser.New(fsys, dir, tt.opts...)
			project, err := p.Parse()
			require.NoError(t, err)

			tasks := project.ListTasks()

			taskNames := lo.Map(tasks, func(task *parser.ResolvedTask, _ int) string {
				return task.Name
			})

			assert.ElementsMatch(t, tt.expectedTasks, taskNames)
		})
	}
}

func TestParser_AbsolutePath(t *testing.T) {
	// The process cannot access the file because it is being used by another process.
	if runtime.GOOS == "windows" {
		t.Skip("TODO")
	}

	tmpDir := t.TempDir()

	tasksFile, err := os.CreateTemp(tmpDir, "tasks-*.yml")
	require.NoError(t, err)

	_, err = tasksFile.WriteString(`- name: Test task
  debug:
    msg: "From task"
`)
	require.NoError(t, err)

	playbookFile, err := os.CreateTemp(tmpDir, "playbook-*.yml")
	require.NoError(t, err)

	playbookSrc := fmt.Sprintf(`- name: test
  hosts: localhost
  connection: local
  tasks:
  - name: test
    include_tasks: "{{ playbook_dir }}/%s"
`, filepath.Base(tasksFile.Name()))

	_, err = playbookFile.WriteString(playbookSrc)
	require.NoError(t, err)

	project, err := parser.New(os.DirFS(tmpDir), ".").Parse()
	require.NoError(t, err)
	tasks := project.ListTasks()
	taskNames := lo.Map(tasks, func(task *parser.ResolvedTask, _ int) string {
		return task.Name
	})

	expected := []string{
		"Test task",
	}
	assert.ElementsMatch(t, expected, taskNames)
}

func TestParse_ResolveVariables(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		opts  []parser.Option
	}{
		{
			name: "vars in task",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  tasks:
    - name: create bucket
      vars:
        public_access: "true"
      s3_bucket:
        name: "{{ bucket }}"
        public_access: "{{ public_access }}"
`,
			},
		},
		{
			name: "vars in play",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
    public_access: "true"
  tasks:
    - name: create bucket
      s3_bucket:
        name: '{{ bucket }}'
        public_access: '{{ public_access }}'
`,
			},
		},
		{
			name: "vars in block",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  tasks:
    - block:
        - name: create bucket
          s3_bucket:
            name: '{{ bucket }}'
            public_access: '{{ public_access }}'
      vars:
        public_access: "true"
`,
			},
		},
		// 		{
		// 			name: "vars from vars_files",
		// 			files: map[string]string{
		// 				"main.yaml": `---
		// - name: test
		//   vars_files:
		//     - vars.yaml
		//   vars:
		//     bucket: test
		//   tasks:
		//     - name: create bucket
		//       s3_bucket:
		//         name: '{{ bucket }}'
		//         public_access: '{{ public_access }}'
		// `,
		// 				"vars.yaml": `public_access: "true"`,
		// 			},
		// 		},
		// 		{
		// 			name: "vars from include_vars",
		// 			files: map[string]string{
		// 				"main.yaml": `---
		// - name: test
		//   vars:
		//     bucket: test
		//   tasks:
		//     - include_vars: vars.yaml
		//     - name: create bucket
		//       s3_bucket:
		//         name: '{{ bucket }}'
		//         public_access: '{{ public_access }}'
		// `,
		// 				"vars.yaml": `public_access: "true"`,
		// 			},
		// 		},
		// 		{
		// 			name: "vars from set_fact",
		// 			files: map[string]string{
		// 				"main.yaml": `---
		// - name: test
		//   vars:
		//     bucket: test
		//   tasks:
		//     - set_fact:
		//         public_access: "true"
		//     - name: create bucket
		//       s3_bucket:
		//         name: '{{ bucket }}'
		//         public_access: '{{ public_access }}'
		// `,
		// 			},
		// 		},
		{
			name: "vars from included tasks",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  tasks:
    - include_tasks: included.yaml
`,
				"included.yaml": `
- name: create bucket
  vars:
    public_access: "true"
  s3_bucket:
    name: '{{ bucket }}'
    public_access: '{{ public_access }}'
`,
			},
		},
		{
			name: "vars from imported tasks",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  tasks:
    - import_tasks: imported.yaml
`,
				"imported.yaml": `
- name: create bucket
  vars:
    public_access: "true"
  s3_bucket:
    name: '{{ bucket }}'
    public_access: '{{ public_access }}'
`,
			},
		},
		{
			name: "vars from role defaults",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  roles:
    - myrole
`,
				"roles/myrole/defaults/main.yaml": `public_access: "true"
bucket: "from-role"
`,
				"roles/myrole/tasks/main.yaml": `
- name: create bucket
  s3_bucket:
    name: '{{ bucket }}'
    public_access: '{{ public_access }}'
`,
			},
		},
		{
			name: "vars from role vars",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  roles:
    - myrole
`,
				"roles/myrole/vars/main.yaml": `public_access: "true"`,
				"roles/myrole/tasks/main.yaml": `
- name: create bucket
  s3_bucket:
    name: '{{ bucket }}'
    public_access: '{{ public_access }}'
`,
			},
		},
		{
			name: "vars from nested role dirs",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  roles:
    - myrole
`,
				"roles/myrole/vars/main/subdir/vars.yaml": `public_access: "foo"`,
				"roles/myrole/vars/main/vars.yaml":        `public_access: "true"`,
				"roles/myrole/tasks/main.yaml": `
- name: create bucket
  s3_bucket:
    name: '{{ bucket }}'
    public_access: '{{ public_access }}'
`,
			},
		},
		{
			name: "vars for host",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: test
  hosts: webservers
  tasks:
    - name: create bucket
      vars:
        public_access: "true"
      s3_bucket:
        name: '{{ bucket }}'
        public_access: '{{ public_access }}'
`,
			},
		},
		{
			name: "with extra vars",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: from-play
  hosts: webservers
  tasks:
    - name: create bucket
      vars:
        public_access: "true"
      s3_bucket:
        name: '{{ bucket }}'
        public_access: '{{ public_access }}'
`,
			},
			opts: []parser.Option{
				parser.WithExtraVars(map[string]any{
					"bucket": "test",
				}),
			},
		},
		{
			name: "with host_vars",
			files: map[string]string{
				"main.yaml": `---
- name: test
  vars:
    bucket: from-play
  hosts: webservers
  tasks:
    - name: create bucket
      vars:
        public_access: "true"
      s3_bucket:
        name: '{{ bucket }}'
        public_access: '{{ public_access }}'
`,
				"host_vars/webservers": ``,
			},
			opts: []parser.Option{
				parser.WithExtraVars(map[string]any{
					"bucket": "test",
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(tt.files)
			p := parser.New(fsys, ".", tt.opts...)
			project, err := p.Parse()
			require.NoError(t, err)

			tasks := project.ListTasks()
			modules := tasks.GetModules("s3_bucket")
			require.Len(t, modules, 1)

			m := modules[0]
			assert.Equal(t, "test", m.StringValue("name").Value())
			assert.Equal(t, "true", m.StringValue("public_access").Value())
		})
	}
}
