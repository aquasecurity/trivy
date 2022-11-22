package misconf

import (
	"context"
	"fmt"
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
			input:      []string{"/"},
			wantTarget: "/",
			wantPaths:  []string{"."},
		},
		{
			input:      []string{"/home/user"},
			wantTarget: "/home/user",
			wantPaths:  []string{"."},
		},
		{
			input:      []string{"/home/user", "/home/user/something"},
			wantTarget: "/home/user",
			wantPaths:  []string{".", "something"},
		},
		{
			input:      []string{"/home/user", "/home/user/something/else"},
			wantTarget: "/home/user",
			wantPaths:  []string{".", "something/else"},
		},
		{
			input:      []string{"/home/user", "/home/user2/something/else"},
			wantTarget: "/home",
			wantPaths:  []string{"user", "user2/something/else"},
		},
		{
			input:      []string{"/foo", "/bar"},
			wantTarget: "/",
			wantPaths:  []string{"foo", "bar"},
		},
		{
			input:      []string{"/", "/bar"},
			wantTarget: "/",
			wantPaths:  []string{".", "bar"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%#v", test.input), func(t *testing.T) {
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
