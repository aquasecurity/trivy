package walker_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestFS_Walk(t *testing.T) {
	tests := []struct {
		name      string
		option    walker.Option
		rootDir   string
		analyzeFn walker.WalkFunc
		wantErr   string
	}{
		{
			name:    "happy path",
			rootDir: "testdata/fs",
			analyzeFn: func(filePath string, _ os.FileInfo, opener analyzer.Opener) error {
				if filePath == "testdata/fs/bar" {
					got, err := opener()
					require.NoError(t, err)

					b, err := io.ReadAll(got)
					require.NoError(t, err)

					assert.Equal(t, "bar", string(b))
				}
				return nil
			},
		},
		{
			name:    "skip file",
			rootDir: "testdata/fs",
			option: walker.Option{
				SkipFiles: []string{"testdata/fs/bar"},
			},
			analyzeFn: func(filePath string, _ os.FileInfo, _ analyzer.Opener) error {
				if filePath == "testdata/fs/bar" {
					assert.Fail(t, "skip files error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "skip dir",
			rootDir: "testdata/fs/",
			option: walker.Option{
				SkipDirs: []string{"/testdata/fs/app"},
			},
			analyzeFn: func(filePath string, _ os.FileInfo, _ analyzer.Opener) error {
				if strings.HasPrefix(filePath, "testdata/fs/app") {
					assert.Fail(t, "skip dirs error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "sad path",
			rootDir: "testdata/fs",
			analyzeFn: func(string, os.FileInfo, analyzer.Opener) error {
				return errors.New("error")
			},
			wantErr: "failed to analyze file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := walker.NewFS()
			err := w.Walk(tt.rootDir, tt.option, tt.analyzeFn)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFS_Walk_GitConfig(t *testing.T) {
	// .git/config and .git/credentials may contain embedded secrets and must
	// be scanned. Subdirectories that are either binary-heavy or high-volume
	// with no secret value must remain skipped:
	//   objects – packed git object store
	//   lfs     – Git LFS binary data
	//   modules – submodule checkouts
	//   logs    – reflog entries (plaintext but high-volume, low-signal)
	//
	// We use t.TempDir() instead of static testdata because git itself ignores
	// nested .git directories inside a repository.
	root := t.TempDir()

	// Files that MUST be scanned
	require.NoError(t, os.WriteFile(filepath.Join(root, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = https://user:token@github.com/org/repo.git\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".git", "credentials"),
		[]byte("https://user:ghp_secret@github.com\n"), 0o644))

	// Directories that MUST be skipped
	skippedDirs := []string{"objects", "lfs", "modules", "logs"}
	for _, d := range skippedDirs {
		require.NoError(t, os.MkdirAll(filepath.Join(root, ".git", d), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, ".git", d, "file"),
			[]byte("content"), 0o644))
	}

	var visitedConfig, visitedCredentials bool
	w := walker.NewFS()
	err := w.Walk(root, walker.Option{}, func(filePath string, _ os.FileInfo, _ analyzer.Opener) error {
		for _, d := range skippedDirs {
			if strings.Contains(filePath, filepath.Join(".git", d)) {
				assert.Failf(t, "skipped dir was walked", ".git/%s must be skipped, got: %s", d, filePath)
			}
		}
		if strings.HasSuffix(filePath, filepath.Join(".git", "config")) {
			visitedConfig = true
		}
		if strings.HasSuffix(filePath, filepath.Join(".git", "credentials")) {
			visitedCredentials = true
		}
		return nil
	})
	require.NoError(t, err)
	assert.True(t, visitedConfig, ".git/config should be scanned")
	assert.True(t, visitedCredentials, ".git/credentials should be scanned")
}

func TestFS_BuildSkipPaths(t *testing.T) {
	tests := []struct {
		name  string
		oses  []string
		paths []string
		base  string
		want  []string
	}{
		// Linux/macOS
		{
			name: "path - abs, base - abs, not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "/foo",
			paths: []string{"/foo/bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - abs, base - rel",
			oses: []string{
				"linux",
				"darwin",
			},
			base: "foo",
			paths: func() []string {
				abs, err := filepath.Abs("foo/bar")
				require.NoError(t, err)
				return []string{abs}
			}(),
			want: []string{"bar"},
		},
		{
			name: "path - rel, base - rel, joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - rel, base - rel, not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"foo/bar/bar"},
			want:  []string{"bar/bar"},
		},
		{
			name: "path - rel with dot, base - rel, removing the leading dot and not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"./foo/bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - rel, base - dot",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  ".",
			paths: []string{"foo/bar"},
			want:  []string{"foo/bar"},
		},
		// Windows
		{
			name:  "path - rel, base - rel. Skip common prefix",
			oses:  []string{"windows"},
			base:  "foo",
			paths: []string{"foo\\bar\\bar"},
			want:  []string{"bar/bar"},
		},
		{
			name:  "path - rel, base - dot, windows",
			oses:  []string{"windows"},
			base:  ".",
			paths: []string{"foo\\bar"},
			want:  []string{"foo/bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !slices.Contains(tt.oses, runtime.GOOS) {
				t.Skipf("Skip path tests for %q", tt.oses)
			}
			got := walker.NewFS().BuildSkipPaths(tt.base, tt.paths)
			assert.Equal(t, tt.want, got)
		})
	}
}
