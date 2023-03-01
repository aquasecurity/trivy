package misconf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
)

func TestScanner_Scan(t *testing.T) {
	tests := []struct {
		name         string
		files        []types.File
		filePatterns []string
		wantFilePath string
		wantFileType string
	}{
		{
			name: "happy path. Dockerfile",
			files: []types.File{
				{
					Path:    "Dockerfile",
					Type:    types.Dockerfile,
					Content: []byte(`FROM alpine`),
				},
			},
			wantFilePath: "Dockerfile",
			wantFileType: types.Dockerfile,
		},
		{
			name: "happy path. Dockerfile with custom file name",
			files: []types.File{
				{
					Path:    "dockerf",
					Type:    types.Dockerfile,
					Content: []byte(`FROM alpine`),
				},
			},
			filePatterns: []string{"dockerfile:dockerf"},
			wantFilePath: "dockerf",
			wantFileType: types.Dockerfile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewScanner(tt.filePatterns, config.ScannerOption{})
			require.NoError(t, err)

			misconfs, err := s.Scan(context.Background(), tt.files)
			require.NoError(t, err)
			assert.Equal(t, 1, len(misconfs), "wrong number of misconfigurations found")
			assert.Equal(t, tt.wantFilePath, misconfs[0].FilePath, "filePaths don't equal")
			assert.Equal(t, tt.wantFileType, misconfs[0].FileType, "fileTypes don't equal")
		})
	}
}

func Test_FindingFSTarget(t *testing.T) {
	tests := []struct {
		input      []string
		wantTarget string
		wantPaths  []string
		wantErr    bool
	}{
		{
			input:   nil,
			wantErr: true,
		},
		{
			input:      []string{string(os.PathSeparator)},
			wantTarget: string(os.PathSeparator),
			wantPaths:  []string{"."},
		},
		{
			input:      []string{filepath.Join(string(os.PathSeparator), "home", "user")},
			wantTarget: filepath.Join(string(os.PathSeparator), "home", "user"),
			wantPaths:  []string{"."},
		},
		{
			input: []string{
				filepath.Join(string(os.PathSeparator), "home", "user"),
				filepath.Join(string(os.PathSeparator), "home", "user", "something"),
			},
			wantTarget: filepath.Join(string(os.PathSeparator), "home", "user"),
			wantPaths:  []string{".", "something"},
		},
		{
			input: []string{
				filepath.Join(string(os.PathSeparator), "home", "user"),
				filepath.Join(string(os.PathSeparator), "home", "user", "something", "else"),
			},
			wantTarget: filepath.Join(string(os.PathSeparator), "home", "user"),
			wantPaths:  []string{".", "something/else"},
		},
		{
			input: []string{
				filepath.Join(string(os.PathSeparator), "home", "user"),
				filepath.Join(string(os.PathSeparator), "home", "user2", "something", "else"),
			},
			wantTarget: filepath.Join(string(os.PathSeparator), "home"),
			wantPaths:  []string{"user", "user2/something/else"},
		},
		{
			input: []string{
				filepath.Join(string(os.PathSeparator), "foo"),
				filepath.Join(string(os.PathSeparator), "bar"),
			},
			wantTarget: string(os.PathSeparator),
			wantPaths:  []string{"foo", "bar"},
		},
		{
			input:      []string{string(os.PathSeparator), filepath.Join(string(os.PathSeparator), "bar")},
			wantTarget: string(os.PathSeparator),
			wantPaths:  []string{".", "bar"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%#v", test.input), func(t *testing.T) {
			if runtime.GOOS == "windows" {
				wantTarget, err := filepath.Abs(test.wantTarget)
				require.NoError(t, err)
				test.wantTarget = filepath.Clean(wantTarget)
			}

			target, paths, err := findFSTarget(test.input)
			if test.wantErr {
				require.Error(t, err)
			} else {
				assert.Equal(t, test.wantTarget, target)
				assert.Equal(t, test.wantPaths, paths)
			}
		})
	}
}

func Test_createPolicyFS(t *testing.T) {
	t.Run("inside cwd", func(t *testing.T) {
		cwd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(cwd, "testdir"), 0750))
		require.NoError(t, os.MkdirAll(filepath.Join(cwd, ".testdir"), 0750))
		defer func() {
			os.RemoveAll(filepath.Join(cwd, "testdir"))
			os.RemoveAll(filepath.Join(cwd, ".testdir"))
		}()

		_, got1, err := createPolicyFS([]string{"testdir"})
		require.NoError(t, err)

		_, got2, err := createPolicyFS([]string{".testdir"})
		require.NoError(t, err)

		assert.NotEqual(t, got1, got2, "testdir and .testdir are different dirs and should not be equal")
	})

	t.Run("outside cwd", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "subdir/testdir"), 0750))
		f, got, err := createPolicyFS([]string{filepath.Join(tmpDir, "subdir/testdir")})
		require.NoError(t, err)
		assert.Equal(t, []string{"."}, got)
		assert.Contains(t, f, "testdir")
	})
}
