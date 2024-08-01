//go:build plugin_integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlugin(t *testing.T) {
	tests := []struct {
		name   string
		plugin string
		golden string
	}{
		{
			// TODO add plugin flags
			name:   "count plugin installed from `index`",
			plugin: "count@v0.2.0",
			golden: "Number of vulnerabilities: 5",
		},
		{
			name:   "count plugin installed from github archive",
			plugin: "https://github.com/aquasecurity/trivy-plugin-count/archive/refs/tags/v0.1.0.zip",
			golden: "Number of vulnerabilities: 5",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tmpDir)

			// Install plugin
			err := execute([]string{
				"plugin",
				"install",
				tt.plugin,
			})
			require.NoError(t, err)

			// Overwrite Stdout to get output of plugin
			tmpFile, err := os.Create(filepath.Join(tmpDir, "tmp.txt"))
			require.NoError(t, err)
			os.Stdout = tmpFile

			// Run Trivy with plugin as output
			err = execute([]string{
				"--cache-dir",
				cacheDir,
				"fs",
				"-f",
				"json",
				"-o",
				"plugin=count",
				"testdata/fixtures/repo/gomod",
			})

			got, err := os.ReadFile(tmpFile.Name())
			require.NoError(t, err)
			require.Equal(t, tt.golden, strings.TrimSpace(string(got)))
		})
	}
}
