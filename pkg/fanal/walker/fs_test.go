package walker_test

import (
	"errors"
	"github.com/aquasecurity/trivy/pkg/custom"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestDir_Walk(t *testing.T) {
	type fields struct {
		skipFiles []string
		skipDirs  []string
		option    custom.Option
	}
	tests := []struct {
		name      string
		fields    fields
		rootDir   string
		analyzeFn walker.WalkFunc
		wantErr   string
	}{
		{
			name:    "happy path",
			rootDir: "testdata/fs",
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
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
			fields: fields{
				skipFiles: []string{"testdata/fs/bar"},
			},
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				if filePath == "testdata/fs/bar" {
					assert.Fail(t, "skip files error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "skip dir",
			rootDir: "testdata/fs/",
			fields: fields{
				skipDirs: []string{"/testdata/fs/app"},
			},
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				if strings.HasPrefix(filePath, "testdata/fs/app") {
					assert.Fail(t, "skip dirs error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "ignore all errors",
			rootDir: "testdata/fs/nosuch",
			fields: fields{
				option: custom.Option{
					ErrorCallback: func(pathname string, err error) error {
						return nil
					},
				},
			},
			analyzeFn: func(string, os.FileInfo, analyzer.Opener) error {
				return nil
			},
		},
		{
			name:    "ignore analysis errors",
			rootDir: "testdata/fs",
			fields: fields{
				option: custom.Option{
					ErrorCallback: func(pathname string, err error) error {
						if errors.Is(err, fs.ErrClosed) {
							return nil
						}
						return err
					},
				},
			},
			analyzeFn: func(string, os.FileInfo, analyzer.Opener) error {
				return fs.ErrClosed
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
			w := walker.NewFS(tt.fields.skipFiles, tt.fields.skipDirs, tt.fields.option)

			err := w.Walk(tt.rootDir, tt.analyzeFn)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
