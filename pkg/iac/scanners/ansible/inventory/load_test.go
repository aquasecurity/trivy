package inventory_test

import (
	"io/fs"
	"os"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
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

	fsys := testutil.CreateFS(files)
	inv := inventory.LoadAuto(fsys, inventory.LoadOptions{
		Sources: []string{"dev", "common"},
	})

	tests := []struct {
		name     string
		hostName string
		expected vars.Vars
	}{
		{
			hostName: "host1",
			expected: vars.Vars{
				"foo":    extHostVar(10), // external host_var from common
				"bar":    extHostVar(2),  // external host_var override file group
				"baz":    hostVar(10),    // file host
				"common": hostVar(10),    // host var from common
			},
		},
		{
			hostName: "host2",
			expected: vars.Vars{
				"foo":    extHostVar(10),     // external host_var override external group
				"bar":    hostVar(15),        // file host
				"baz":    extHostVar(20),     // external host_var override file host
				"common": extGroupVar("yes"), // from group_vars
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostName, func(t *testing.T) {
			got := inv.ResolveVars(tt.hostName, make(inventory.LoadedVars))
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestLoadAuto_AbsolutePath(t *testing.T) {
	// The process cannot access the file because it is being used by another process.
	if runtime.GOOS == "windows" {
		t.Skip("TODO")
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "hosts-*.yml")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(`
group1:
  hosts:
    host1:
      baz: 5
  vars:
    bar: 20
`)
	require.NoError(t, err)

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
	}
	fsys := testutil.CreateFS(files)

	opts := inventory.LoadOptions{
		Sources: []string{"dev", tmpFile.Name()},
	}

	inv := inventory.LoadAuto(fsys, opts)

	tests := []struct {
		name     string
		hostName string
		expected vars.Vars
	}{
		{
			hostName: "host1",
			expected: vars.Vars{
				"bar": groupVar(20), // from second file (group)
				"baz": hostVar(5),   // from second file (host)
			},
		},
		{
			hostName: "host2",
			expected: vars.Vars{
				"bar": hostVar(15), // from first file (host)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostName, func(t *testing.T) {
			got := inv.ResolveVars(tt.hostName, make(inventory.LoadedVars))
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestLoadAuto_EmptySources(t *testing.T) {
	inv := inventory.LoadAuto(fstest.MapFS{}, inventory.LoadOptions{})

	localhostVars := vars.Vars{
		"foo": hostVar("test"),
	}
	got := inv.ResolveVars("localhost", inventory.LoadedVars{
		inventory.ScopeHost: map[string]vars.Vars{
			"localhost": localhostVars,
		},
	})

	assert.Equal(t, localhostVars, got)
}

func TestLoadAuto_NonExistentSource(t *testing.T) {
	opts := inventory.LoadOptions{
		InventoryPath: "nonexistent",
	}

	inv := inventory.LoadAuto(fstest.MapFS{}, opts)
	localhostVars := vars.Vars{
		"foo": hostVar("test"),
	}
	got := inv.ResolveVars("localhost", inventory.LoadedVars{
		inventory.ScopeHost: map[string]vars.Vars{
			"localhost": localhostVars,
		},
	})

	assert.Equal(t, localhostVars, got)
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
	rootSrc := fsutils.NewFileSource(fsys, ".")

	tests := []struct {
		name     string
		opts     inventory.LoadOptions
		expected []inventory.InventorySource
	}{
		{
			name: "single file",
			opts: inventory.LoadOptions{Sources: []string{"hosts.yml"}},
			expected: []inventory.InventorySource{
				inventory.HostFileSource{
					File:    rootSrc.Join("hosts.yml"),
					VarsDir: rootSrc,
				},
			},
		},
		{
			name: "single file in subdirectory",
			opts: inventory.LoadOptions{Sources: []string{"inv/hosts.yml"}},
			expected: []inventory.InventorySource{
				inventory.HostFileSource{
					File:    rootSrc.Join("inv", "hosts.yml"),
					VarsDir: rootSrc.Join("inv"),
				},
			},
		},
		{
			name: "nested directories with vars",
			opts: inventory.LoadOptions{Sources: []string{"inv"}},
			expected: []inventory.InventorySource{
				inventory.HostsDirsSource{
					Dirs: []fsutils.FileSource{
						rootSrc.Join("inv"),
						rootSrc.Join("inv", "one"),
						rootSrc.Join("inv", "two"),
					},
					VarsDir: rootSrc.Join("inv"),
				},
			},
		},
		{
			name: "inline hosts list",
			opts: inventory.LoadOptions{Sources: []string{"host1,host2"}},
			expected: []inventory.InventorySource{
				inventory.InlineHostsSource{Hosts: []string{"host1", "host2"}},
			},
		},
		{
			name: "empty sources with cfg path",
			opts: inventory.LoadOptions{
				InventoryPath: "hosts.yml",
			},
			expected: []inventory.InventorySource{
				inventory.HostFileSource{File: rootSrc.Join("hosts.yml"), VarsDir: rootSrc},
			},
		},
		{
			name: "directory without hosts files",
			opts: inventory.LoadOptions{Sources: []string{"emptydir"}},
			expected: []inventory.InventorySource{
				inventory.HostsDirsSource{VarsDir: rootSrc.Join("emptydir")},
			},
		},
		{
			name: "multiple sources",
			opts: inventory.LoadOptions{Sources: []string{"inv/one", "inv/two"}},
			expected: []inventory.InventorySource{
				inventory.HostsDirsSource{
					Dirs:    []fsutils.FileSource{rootSrc.Join("inv", "one")},
					VarsDir: rootSrc.Join("inv", "one"),
				},
				inventory.HostsDirsSource{
					Dirs:    []fsutils.FileSource{rootSrc.Join("inv", "two")},
					VarsDir: rootSrc.Join("inv", "two"),
				},
			},
		},
		{
			name:     "no sources",
			opts:     inventory.LoadOptions{},
			expected: []inventory.InventorySource{},
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

func TestResolveInventorySources_AbsolutePath(t *testing.T) {
	// The process cannot access the file because it is being used by another process.
	if runtime.GOOS == "windows" {
		t.Skip("TODO")
	}

	// create a temporary inventory file
	tmpFile, err := os.CreateTemp(t.TempDir(), "hosts-*.yml")
	require.NoError(t, err)

	opts := inventory.LoadOptions{
		InventoryPath: tmpFile.Name(),
	}

	fsys := fstest.MapFS{}

	res, err := inventory.ResolveSources(fsys, opts)
	require.NoError(t, err)

	fileSrc := fsutils.NewFileSource(nil, tmpFile.Name())

	expected := []inventory.InventorySource{
		inventory.HostFileSource{
			File:    fileSrc,
			VarsDir: fileSrc.Dir(),
		},
	}

	require.ElementsMatch(t, expected, res)
}
