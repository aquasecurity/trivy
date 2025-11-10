//go:build integration

package integration

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

// TestPlugin tests Trivy plugins.
//
// NOTE: This test CAN update golden files with the -update flag because the golden files
// used here are not shared with other tests. These plugin-specific golden files are unique
// to this test and should be updated here.
func TestPlugin(t *testing.T) {
	tests := []struct {
		name       string
		plugin     string
		pluginArgs string
		golden     string
	}{
		{
			name:   "count plugin installed from `index`",
			plugin: "count@v0.2.0",
			golden: goldenCountPlugin020,
		},
		{
			name:       "count plugin installed from github archive",
			plugin:     "https://github.com/aquasecurity/trivy-plugin-count/archive/refs/tags/v0.1.0.zip",
			pluginArgs: "--published-before=2020-01-01",
			golden:     goldenCountPlugin010WithBeforeFlag,
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)
	tempStdOut := setTempStdout(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can overwrite stdout for `_default_Manager` only once.
			// So we need to clear the temporary stdout file before each test case.
			clearFile(t, tempStdOut)

			t.Setenv("XDG_DATA_HOME", t.TempDir())

			// Install plugin
			err := execute([]string{
				"plugin",
				"install",
				tt.plugin,
			})
			require.NoError(t, err)

			// Get list of plugins
			err = execute([]string{
				"plugin",
				"list",
			})
			require.NoError(t, err)

			// Run Trivy with plugin as output
			args := []string{
				"--cache-dir",
				cacheDir,
				"fs",
				"-f",
				"json",
				"-o",
				"plugin=count",
				"testdata/fixtures/repo/pip",
			}

			if tt.pluginArgs != "" {
				args = append(args, "--output-plugin-arg", tt.pluginArgs)
			}

			err = execute(args)
			require.NoError(t, err)

			if *update {
				fsutils.CopyFile(tempStdOut.Name(), tt.golden)
			}

			compareRawFiles(t, tt.golden, tempStdOut.Name())
		})
	}
}

func setTempStdout(t *testing.T) *os.File {
	tmpFile := filepath.Join(t.TempDir(), "output.txt")
	f, err := os.Create(tmpFile)
	require.NoError(t, err)

	// Overwrite Stdout to get output of plugin
	defaultStdout := os.Stdout
	os.Stdout = f
	t.Cleanup(func() {
		os.Stdout = defaultStdout
		f.Close()
	})
	return f
}

func clearFile(t *testing.T, file *os.File) {
	_, err := file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	_, err = file.Write([]byte{})
	require.NoError(t, err)
}
