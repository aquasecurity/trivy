package clean_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/clean"
	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name      string
		cleanOpts flag.CleanOptions
		wantErr   bool
		checkFunc func(*testing.T, string)
	}{
		{
			name: "clean all",
			cleanOpts: flag.CleanOptions{
				CleanAll: true,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, dir string) {
				assert.NoDirExists(t, filepath.Join(dir, "fanal"))
				assert.NoDirExists(t, filepath.Join(dir, "db"))
				assert.NoDirExists(t, filepath.Join(dir, "java-db"))
				assert.NoDirExists(t, filepath.Join(dir, "policy"))
				assert.NoDirExists(t, filepath.Join(dir, "vex"))
				assert.DirExists(t, dir)
			},
		},
		{
			name: "clean scan cache",
			cleanOpts: flag.CleanOptions{
				CleanScanCache: true,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, dir string) {
				assert.NoDirExists(t, filepath.Join(dir, "fanal"))
				assert.DirExists(t, filepath.Join(dir, "db"))
				assert.DirExists(t, filepath.Join(dir, "java-db"))
				assert.DirExists(t, filepath.Join(dir, "policy"))
				assert.DirExists(t, filepath.Join(dir, "vex"))
			},
		},
		{
			name: "clean vulnerability DB",
			cleanOpts: flag.CleanOptions{
				CleanVulnerabilityDB: true,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, dir string) {
				assert.NoDirExists(t, filepath.Join(dir, "db"))
				assert.DirExists(t, filepath.Join(dir, "fanal"))
				assert.DirExists(t, filepath.Join(dir, "java-db"))
				assert.DirExists(t, filepath.Join(dir, "policy"))
				assert.DirExists(t, filepath.Join(dir, "vex"))
			},
		},
		{
			name: "clean Java DB",
			cleanOpts: flag.CleanOptions{
				CleanJavaDB: true,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, dir string) {
				assert.NoDirExists(t, filepath.Join(dir, "java-db"))
				assert.DirExists(t, filepath.Join(dir, "fanal"))
				assert.DirExists(t, filepath.Join(dir, "db"))
				assert.DirExists(t, filepath.Join(dir, "policy"))
				assert.DirExists(t, filepath.Join(dir, "vex"))
			},
		},
		{
			name: "clean check bundle",
			cleanOpts: flag.CleanOptions{
				CleanChecksBundle: true,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, dir string) {
				assert.NoDirExists(t, filepath.Join(dir, "policy"))
				assert.DirExists(t, filepath.Join(dir, "fanal"))
				assert.DirExists(t, filepath.Join(dir, "db"))
				assert.DirExists(t, filepath.Join(dir, "java-db"))
				assert.DirExists(t, filepath.Join(dir, "vex"))
			},
		},
		{
			name: "clean vex repositories",
			cleanOpts: flag.CleanOptions{
				CleanVEXRepositories: true,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, dir string) {
				assert.DirExists(t, filepath.Join(dir, "policy"))
				assert.DirExists(t, filepath.Join(dir, "fanal"))
				assert.DirExists(t, filepath.Join(dir, "db"))
				assert.DirExists(t, filepath.Join(dir, "java-db"))
				assert.NoDirExists(t, filepath.Join(dir, "vex"))
			},
		},
		{
			name:    "no clean option specified",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for testing
			tempDir := t.TempDir()

			// Create test directories and files
			createTestFiles(t, tempDir)

			opts := flag.Options{
				GlobalOptions: flag.GlobalOptions{
					CacheDir: tempDir,
				},
				CacheOptions: flag.CacheOptions{
					CacheBackend: string(cache.TypeFS),
				},
				CleanOptions: tt.cleanOpts,
			}

			err := clean.Run(context.Background(), opts)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.checkFunc != nil {
				tt.checkFunc(t, tempDir)
			}
		})
	}
}

func createTestFiles(t *testing.T, dir string) {
	subdirs := []string{
		"fanal",
		"db",
		"java-db",
		"policy",
		"vex",
	}
	for _, subdir := range subdirs {
		err := os.MkdirAll(filepath.Join(dir, subdir), 0755)
		require.NoError(t, err)

		testFile := filepath.Join(dir, subdir, "testfile.txt")
		err = os.WriteFile(testFile, []byte("test content"), 0644)
		require.NoError(t, err)
	}
}
