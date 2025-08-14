package inventory_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/inventory"
)

func TestResolveInventorySources(t *testing.T) {
	tests := []struct {
		name     string
		fsys     fs.FS
		opts     inventory.LoadOptions
		expected []inventory.InventorySource
	}{
		{
			name: "single file",
			fsys: fstest.MapFS{
				"hosts.yml": &fstest.MapFile{Data: []byte("")},
			},
			opts: inventory.LoadOptions{Sources: []string{"hosts.yml"}},
			expected: []inventory.InventorySource{
				{
					HostsFile:    "hosts.yml",
					InventoryDir: ".",
				},
			},
		},
		{
			name: "nested directories with vars",
			fsys: fstest.MapFS{
				"one/hosts.yml":                &fstest.MapFile{Data: []byte("")},
				"one/group_vars/group1.yml":    &fstest.MapFile{Data: []byte("")},
				"one/foo/hosts.yml":            &fstest.MapFile{Data: []byte("")},
				"one/foo/host_vars/hosts1.yml": &fstest.MapFile{Data: []byte("")},
			},
			opts: inventory.LoadOptions{Sources: []string{"one"}},
			expected: []inventory.InventorySource{
				{
					InventoryDir: "one",
				},
				{
					InventoryDir: "one/foo",
				},
			},
		},
		{
			name: "inline hosts list",
			fsys: fstest.MapFS{},
			opts: inventory.LoadOptions{Sources: []string{"host1,host2"}},
			expected: []inventory.InventorySource{
				{InlineHosts: []string{"host1", "host2"}},
			},
		},
		{
			name: "empty sources with cfg path",
			fsys: fstest.MapFS{
				"cfghosts.yml": &fstest.MapFile{Data: []byte("")},
			},
			opts: inventory.LoadOptions{
				InventoryPath: "cfghosts.yml",
			},
			expected: []inventory.InventorySource{
				{HostsFile: "cfghosts.yml", InventoryDir: "."},
			},
		},
		{
			name: "directory without files is skipped",
			fsys: fstest.MapFS{
				"emptydir": &fstest.MapFile{Mode: fs.ModeDir},
			},
			opts:     inventory.LoadOptions{Sources: []string{"emptydir"}},
			expected: []inventory.InventorySource{},
		},
		{
			name: "multiple nested directories",
			fsys: fstest.MapFS{
				"inv1/hosts.yml": &fstest.MapFile{Data: []byte("")},
				"inv2/hosts.yml": &fstest.MapFile{Data: []byte("")},
			},
			opts: inventory.LoadOptions{Sources: []string{"inv1", "inv2"}},
			expected: []inventory.InventorySource{
				{InventoryDir: "inv1"},
				{InventoryDir: "inv2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := inventory.ResolveSources(tt.fsys, tt.opts)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.expected, res)
		})
	}
}
