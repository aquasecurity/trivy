package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestTask_GetModule(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		moduleName string
		want       bool
	}{
		{
			name: "happy",
			src: `name: Ensure apache is at the latest version
ansible.builtin.yum:
  name: httpd
  state: latest`,
			moduleName: "ansible.builtin.yum",
			want:       true,
		},
		{
			name: "fail",
			src: `name: Ensure apache is at the latest version
ansible.builtin.yum:
  name: httpd
  state: latest`,
			moduleName: "ansible.builtin.service",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var task Task
			err := yaml.Unmarshal([]byte(tt.src), &task)
			require.NoError(t, err)

			_, exists := task.getModule(tt.moduleName)
			assert.Equal(t, tt.want, exists)
		})
	}
}
