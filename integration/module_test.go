//go:build module_integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func TestModule(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		golden string
	}{
		{
			name:   "spring4shell jre 8, severity update",
			input:  "testdata/fixtures/images/spring4shell-jre8.tar.gz",
			golden: "testdata/spring4shell-jre8.json.golden",
		},
		{
			name:   "spring4shell jre 11, no severity update",
			input:  "testdata/fixtures/images/spring4shell-jre11.tar.gz",
			golden: "testdata/spring4shell-jre11.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set up module dir
	moduleDir := filepath.Join(cacheDir, module.RelativeDir)
	err := os.MkdirAll(moduleDir, 0700)
	require.NoError(t, err)

	// Set up Spring4Shell module
	t.Setenv("XDG_DATA_HOME", cacheDir)
	_, err = utils.CopyFile(filepath.Join("../", "examples", "module", "spring4shell", "spring4shell.wasm"),
		filepath.Join(moduleDir, "spring4shell.wasm"))
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{"--cache-dir", cacheDir, "image", "--ignore-unfixed", "--format", "json",
				"--skip-update", "--offline-scan", "--input", tt.input}

			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			osArgs = append(osArgs, []string{"--output", outputFile}...)

			// Run Trivy
			err = execute(osArgs)
			assert.NoError(t, err)

			// Compare want and got
			compareReports(t, tt.golden, outputFile)
		})
	}
}
