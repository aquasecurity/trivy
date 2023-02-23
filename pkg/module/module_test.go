package module_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
		enableModules           []string
		wantAnalyzerVersions    analyzer.Versions
		wantPostScannerVersions map[string]int
		wantErr                 bool
	}{
		{
			name:       "happy path",
			moduleName: "happy",
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers: map[string]int{
					"happy": 1,
				},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{
				"happy": 1,
			},
		},
		{
			name:       "only analyzer",
			moduleName: "analyzer",
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers: map[string]int{
					"analyzer": 1,
				},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{},
		},
		{
			name:       "only post scanner",
			moduleName: "scanner",
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers:     map[string]int{},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{
				"scanner": 2,
			},
		},
		{
			name:        "no module dir",
			noModuleDir: true,
			moduleName:  "happy",
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers:     map[string]int{},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{},
		},
		{
			name:          "enable custom modules under dir",
			moduleName:    "happy,analyzer,scanner",
			enableModules: []string{"happy", "analyzer"},
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers: map[string]int{
					"happy":    1,
					"analyzer": 1,
				},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{
				"happy": 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var modulePaths []string
			if len(tt.enableModules) > 0 {
				enableModules := strings.Split(tt.moduleName, ",")
				for _, enableModule := range enableModules {
					modulePaths = append(modulePaths, filepath.Join("testdata", enableModule, enableModule+".wasm"))
				}
			} else {
				modulePaths = []string{filepath.Join("testdata", tt.moduleName, tt.moduleName+".wasm")}
			}

			// Set up a temp dir for modules
			tmpDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tmpDir)
			moduleDir := filepath.Join(tmpDir, module.RelativeDir)

			// WASM modules must be generated before running this test.
			for _, modulePath := range modulePaths {
				if _, err := os.Stat(modulePath); os.IsNotExist(err) {
					require.Fail(t, "missing WASM modules, try 'make test' or 'make generate-test-modules'")
				}

				if !tt.noModuleDir {
					err := os.MkdirAll(moduleDir, 0777)
					require.NoError(t, err)

					// Copy the wasm module for testing
					_, err = utils.CopyFile(modulePath, filepath.Join(moduleDir, filepath.Base(modulePath)))
					require.NoError(t, err)
				}
			}
			m, err := module.NewManager(context.Background(), module.WithEnableModules(tt.enableModules))
			require.NoError(t, err)

			// Register analyzer and post scanner from WASM module
			m.Register()
			defer func() {
				tt.enableModules = append(tt.enableModules, tt.moduleName)
				for _, moduleName := range tt.enableModules {
					analyzer.DeregisterAnalyzer(analyzer.Type(moduleName))
					post.DeregisterPostScanner(moduleName)
				}
			}()

			// Confirm the analyzer is registered
			a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got := a.AnalyzerVersions()
			assert.Equal(t, tt.wantAnalyzerVersions, got)

			// Confirm the post scanner is registered
			gotScannerVersions := post.ScannerVersions()
			assert.Equal(t, tt.wantPostScannerVersions, gotScannerVersions)
		})
	}
}
