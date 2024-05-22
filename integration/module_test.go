//go:build module_integration

package integration

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/scanner/post"
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"image",
				"--ignore-unfixed",
				"--format",
				"json",
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
				post.DeregisterPostScanner("spring4shell")
			})

			// Run Trivy
			runTest(t, osArgs, tt.golden, "", types.FormatJSON, runOptions{})
		})
	}
}
