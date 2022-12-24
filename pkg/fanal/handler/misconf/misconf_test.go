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

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_Handle(t *testing.T) {
	tests := []struct {
		name         string
		files        map[types.HandlerType][]types.File
		filePatterns []string
		wantFilePath string
		wantFileType string
	}{
		{
			name: "happy path. Dockerfile",
			files: map[types.HandlerType][]types.File{
				types.MisconfPostHandler: {
					{
						Path:    "Dockerfile",
						Type:    types.Dockerfile,
						Content: []byte(`FROM alpine`),
					},
				},
			},
			wantFilePath: "Dockerfile",
			wantFileType: types.Dockerfile,
		},
		{
			name: "happy path. Dockerfile with custom file name",
			files: map[types.HandlerType][]types.File{
				types.MisconfPostHandler: {
					{
						Path:    "dockerf",
						Type:    types.Dockerfile,
						Content: []byte(`FROM alpine`),
					},
				},
			},
			filePatterns: []string{"dockerfile:dockerf"},
			wantFilePath: "dockerf",
			wantFileType: types.Dockerfile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &analyzer.AnalysisResult{
				Files: tt.files,
			}
			misconfHandler, err := newMisconfPostHandler(artifact.Option{FilePatterns: tt.filePatterns})
			assert.NoError(t, err)
			blobInfo := &types.BlobInfo{}

			err = misconfHandler.Handle(context.Background(), result, blobInfo)
			assert.NoError(t, err)
			assert.Equal(t, 1, len(blobInfo.Misconfigurations), "wrong number of misconfigurations found")
			assert.Equal(t, tt.wantFilePath, blobInfo.Misconfigurations[0].FilePath, "filePaths don't equal")
			assert.Equal(t, tt.wantFileType, blobInfo.Misconfigurations[0].FileType, "fileTypes don't equal")
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
