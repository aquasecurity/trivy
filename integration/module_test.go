//go:build module_integration

package integration

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/types"
)

// TestModule tests Trivy with Wasm modules.
//
// NOTE: This test CAN update golden files with the -update flag because the golden files
// used here are not shared with other tests. These module-specific golden files are unique
// to this test and should be updated here.
func TestModule(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		golden string
	}{
		{
			name:   "spring4shell jre 8, severity update",
			input:  "testdata/fixtures/images/spring4shell-jre8.tar.gz",
			golden: goldenSpring4ShellJRE8,
		},
		{
			name:   "spring4shell jre 11, no severity update",
			input:  "testdata/fixtures/images/spring4shell-jre11.tar.gz",
			golden: goldenSpring4ShellJRE11,
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"image",
				"--ignore-unfixed",
				"--format",
				"json",
				"--list-all-pkgs=false",
				"--skip-db-update",
				"--offline-scan",
				"--quiet",
				"--module-dir",
				filepath.Join("../", "examples", "module", "spring4shell"),
				"--input",
				tt.input,
			}

			t.Cleanup(func() {
				analyzer.DeregisterAnalyzer("spring4shell")
				extension.DeregisterHook("spring4shell")
			})

			// Run Trivy
			runTest(t, osArgs, tt.golden, types.FormatJSON, runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: nil, // Do not use overrides - golden files are generated from this test as the canonical source
			})
		})
	}
}
