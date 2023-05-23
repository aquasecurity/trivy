package module_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/scanner/post"
)

func TestManager_Register(t *testing.T) {
	if runtime.GOOS == "windows" {
		// WASM tests difficult on Windows
		t.Skip("Test satisfied adequately by Linux tests")
	}
	tests := []struct {
		name                    string
		moduleDir               string
		enabledModules          []string
		wantAnalyzerVersions    analyzer.Versions
		wantPostScannerVersions map[string]int
		wantErr                 bool
	}{
		{
			name:      "happy path",
			moduleDir: "testdata/happy",
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
			name:      "only analyzer",
			moduleDir: "testdata/analyzer",
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers: map[string]int{
					"analyzer": 1,
				},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{},
		},
		{
			name:      "only post scanner",
			moduleDir: "testdata/scanner",
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers:     map[string]int{},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{
				"scanner": 2,
			},
		},
		{
			name:      "no module dir",
			moduleDir: "no-such-dir",
			wantAnalyzerVersions: analyzer.Versions{
				Analyzers:     map[string]int{},
				PostAnalyzers: map[string]int{},
			},
			wantPostScannerVersions: map[string]int{},
		},
		{
			name:      "pass enabled modules",
			moduleDir: "testdata",
			enabledModules: []string{
				"happy",
				"analyzer",
			},
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

	// Confirm that wasm modules are generated beforehand
	var count int
	err := filepath.WalkDir("testdata", func(path string, d fs.DirEntry, err error) error {
		if filepath.Ext(path) == ".wasm" {
			count++
		}
		return nil
	})
	require.NoError(t, err)
	// WASM modules must be generated before running the tests.
	require.Equal(t, count, 3, "missing WASM modules, try 'make test' or 'make generate-test-modules'")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := module.NewManager(context.Background(), module.Options{
				Dir:            tt.moduleDir,
				EnabledModules: tt.enabledModules,
			})
			require.NoError(t, err)

			// Register analyzer and post scanner from WASM module
			m.Register()

			// Remove registered analyzers and post scanners so that it will not affect other tests.
			defer m.Deregister()

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
