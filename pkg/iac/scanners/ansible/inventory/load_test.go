package inventory_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/inventory"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func TestLoadAuto(t *testing.T) {
	files := map[string]string{

		"dev/hosts": `
group1:
  hosts:
    host1:
      baz: 10
    host2:	
      bar: 15
  vars:
    bar: 10
`,

		//  host vars
		"dev/host_vars/host1.yaml": `
foo: 1
bar: 2
`,
		"dev/host_vars/host2.yaml": `
foo: 10
baz: 20
`,

		// group vars
		"dev/group_vars/group1.yaml": `
common: "yes"
foo: 5
`,

		// test inventory
		"common/hosts": `
group1:
  hosts:
    host1:
      common: 10
`,

		// common
		"common/group_vars/group1.yaml": `
foo: 5
`,

		"common/host_vars/host1.yaml": `
foo: 10
`,
	}

	fsys := testutil.CreateFS(t, files)
	inv, err := inventory.LoadAuto(fsys, inventory.LoadOptions{
		Sources: []string{"dev", "common"},
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		hostName string
		expected vars.Vars
	}{
		{
			name:     "host1 merged vars",
			hostName: "host1",
			expected: vars.Vars{
				"foo":    10, // external host_var from common
				"bar":    2,  // external host_var override file group
				"baz":    10, // file host
				"common": 10, // external group_vars from common
			},
		},
		{
			name:     "host2 merged vars",
			hostName: "host2",
			expected: vars.Vars{
				"foo":    10,    // external host_var override external group
				"bar":    15,    // file host
				"baz":    20,    // external host_var override file host
				"common": "yes", // from group_vars
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostName, func(t *testing.T) {
			got := inv.ResolveVars(tt.hostName, make(vars.LoadedVars))
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestResolveInventorySources(t *testing.T) {

	files := map[string]*fstest.MapFile{
		"emptydir": {
			Mode: fs.ModeDir,
		},
		"hosts.yml":                     {},
		"inv/hosts.yml":                 {},
		"inv/group_vars/group1.yml":     {},
		"inv/one/hosts.yml":             {},
		"inv/one/host_vars/hosts1.yml":  {},
		"inv/two/hosts.yml":             {},
		"inv/two/group_vars/group1.yml": {},
	}

	fsys := fstest.MapFS(files)

	tests := []struct {
		name     string
		opts     inventory.LoadOptions
		expected []inventory.InventorySource
	}{
		{
			name: "single file",
			opts: inventory.LoadOptions{Sources: []string{"hosts.yml"}},
			expected: []inventory.InventorySource{
				{
					HostsDirs: []string{"hosts.yml"},
					VarsDir:   ".",
				},
			},
		},
		{
			name: "single file in subdirectory",
			opts: inventory.LoadOptions{Sources: []string{"inv/hosts.yml"}},
			expected: []inventory.InventorySource{
				{
					HostsDirs: []string{"inv/hosts.yml"},
					VarsDir:   "inv",
				},
			},
		},
		{
			name: "nested directories with vars",
			opts: inventory.LoadOptions{Sources: []string{"inv"}},
			expected: []inventory.InventorySource{
				{
					HostsDirs: []string{"inv", "inv/one", "inv/two"},
					VarsDir:   "inv",
				},
			},
		},
		{
			name: "inline hosts list",
			opts: inventory.LoadOptions{Sources: []string{"host1,host2"}},
			expected: []inventory.InventorySource{
				{InlineHosts: []string{"host1", "host2"}},
			},
		},
		{
			name: "empty sources with cfg path",
			opts: inventory.LoadOptions{
				InventoryPath: "hosts.yml",
			},
			expected: []inventory.InventorySource{
				{HostsDirs: []string{"hosts.yml"}, VarsDir: "."},
			},
		},
		{
			name:     "directory without hosts files",
			opts:     inventory.LoadOptions{Sources: []string{"emptydir"}},
			expected: []inventory.InventorySource{{VarsDir: "emptydir"}},
		},
		{
			name: "multiple sources",
			opts: inventory.LoadOptions{Sources: []string{"inv/one", "inv/two"}},
			expected: []inventory.InventorySource{
				{HostsDirs: []string{"inv/one"}, VarsDir: "inv/one"},
				{HostsDirs: []string{"inv/two"}, VarsDir: "inv/two"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := inventory.ResolveSources(fsys, tt.opts)
			require.NoError(t, err)
			require.ElementsMatch(t, tt.expected, res)
		})
	}
}
