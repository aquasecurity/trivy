package module_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/scanner/post"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func TestManager_Register(t *testing.T) {
	if runtime.GOOS == "windows" {
		// WASM tests difficult on Windows
		t.Skip("Test satisfied adequately by Linux tests")
	}
	tests := []struct {
		name                    string
		noModuleDir             bool
		moduleName              string
		wantAnalyzerVersions    map[string]int
		wantPostScannerVersions map[string]int
		wantErr                 bool
	}{
		{
			name:       "happy path",
			moduleName: "happy",
			wantAnalyzerVersions: map[string]int{
				"happy": 1,
			},
			wantPostScannerVersions: map[string]int{
				"happy": 1,
			},
		},
		{
			name:       "only analyzer",
			moduleName: "analyzer",
			wantAnalyzerVersions: map[string]int{
				"analyzer": 1,
			},
			wantPostScannerVersions: map[string]int{},
		},
		{
			name:                 "only post scanner",
			moduleName:           "scanner",
			wantAnalyzerVersions: map[string]int{},
			wantPostScannerVersions: map[string]int{
				"scanner": 2,
			},
		},
		{
			name:                    "no module dir",
			noModuleDir:             true,
			moduleName:              "happy",
			wantAnalyzerVersions:    map[string]int{},
			wantPostScannerVersions: map[string]int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modulePath := filepath.Join("testdata", tt.moduleName, tt.moduleName+".wasm")

			// WASM modules must be generated before running this test.
			if _, err := os.Stat(modulePath); os.IsNotExist(err) {
				require.Fail(t, "missing WASM modules, try 'make test' or 'make generate-test-modules'")
			}

			// Set up a temp dir for modules
			tmpDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tmpDir)
			moduleDir := filepath.Join(tmpDir, module.RelativeDir)

			if !tt.noModuleDir {
				err := os.MkdirAll(moduleDir, 0777)
				require.NoError(t, err)

				// Copy the wasm module for testing
				_, err = utils.CopyFile(modulePath, filepath.Join(moduleDir, filepath.Base(modulePath)))
				require.NoError(t, err)
			}

			m, err := module.NewManager(context.Background())
			require.NoError(t, err)

			// Register analyzer and post scanner from WASM module
			m.Register()
			defer func() {
				analyzer.DeregisterAnalyzer(analyzer.Type(tt.moduleName))
				post.DeregisterPostScanner(tt.moduleName)
			}()

			// Confirm the analyzer is registered
			a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got := a.AnalyzerVersions()
			assert.Equal(t, tt.wantAnalyzerVersions, got)

			// Confirm the post scanner is registered
			got = post.ScannerVersions()
			assert.Equal(t, tt.wantPostScannerVersions, got)
		})
	}
}
