package parser_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
)

func TestFindProjects(t *testing.T) {
	tests := []struct {
		name     string
		fsys     fs.FS
		dir      string
		expected []string
	}{
		{
			name: "single project with ansible.cfg",
			fsys: fstest.MapFS{
				"project1/ansible.cfg":     &fstest.MapFile{Data: []byte("[defaults]\n")},
				"project1/inventory/hosts": &fstest.MapFile{Data: []byte("[all]\nlocalhost\n")},
			},
			dir:      "project1",
			expected: []string{"project1"},
		},
		{
			name: "no projects",
			fsys: fstest.MapFS{
				"random/file.txt": &fstest.MapFile{Data: []byte("hello")},
			},
			dir:      ".",
			expected: nil,
		},
		{
			name: "project detected by playbook yaml",
			fsys: fstest.MapFS{
				"proj/main.yml": &fstest.MapFile{Data: []byte(`- hosts: all
  tasks:
    - debug: msg=hello
  `)},
			},
			dir:      "proj",
			expected: []string{"proj"},
		},
		{
			name: "nested projects",
			fsys: fstest.MapFS{
				"proj1/ansible.cfg": &fstest.MapFile{Data: []byte("[defaults]\n")},
				"proj2/main.yaml": &fstest.MapFile{Data: []byte(`- hosts: all
  tasks:
    - debug: msg=hello
`)},
				"proj1/roles/role1/tasks/main.yml": &fstest.MapFile{Data: []byte("- debug: msg=ok")},
			},
			dir:      ".",
			expected: []string{"proj1", "proj2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.FindProjects(tt.fsys, tt.dir)
			require.NoError(t, err)

			assert.ElementsMatch(t, tt.expected, got)
		})
	}
}
