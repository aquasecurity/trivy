package vm_test

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ebsfile "github.com/masahiro331/go-ebs-file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/misconf"
	xio "github.com/aquasecurity/trivy/pkg/x/io"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
)

const (
	ebsPrefix  = string(vm.TypeEBS) + ":"
	filePrefix = string(vm.TypeFile) + ":"
)

type mockWalker struct {
	root string
}

func (m *mockWalker) Walk(_ *io.SectionReader, _ string, _ walker.Option, fn walker.WalkFunc) error {
	return filepath.WalkDir(m.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		opener := func() (xio.ReadSeekCloserAt, error) {
			return os.Open(path)
		}
		relPath, err := filepath.Rel(m.root, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)
		return fn(relPath, info, opener)
	})
}

func TestNewArtifact(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "happy path for file",
			target:  "testdata/mock.img",
			wantErr: assert.NoError,
		},
		{
			name:    "happy path for EBS",
			target:  "ebs:ebs-012345",
			wantErr: assert.NoError,
		},
		{
			name:   "sad path unsupported vm format",
			target: "testdata/monolithicSparse.vmdk",
			wantErr: func(t assert.TestingT, err error, args ...any) bool {
				return assert.ErrorContains(t, err, "unsupported type error")
			},
		},
		{
			name:   "sad path file not found",
			target: "testdata/no-file",
			wantErr: func(t assert.TestingT, err error, args ...any) bool {
				return assert.ErrorContains(t, err, "file open error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &mockWalker{root: "testdata"}
			_, err := vm.NewArtifact(tt.target, nil, w, artifact.Option{Parallel: 3})
			tt.wantErr(t, err, fmt.Sprintf("NewArtifact(%v, nil, nil)", tt.target))
		})
	}
}

func TestArtifact_Inspect(t *testing.T) {
	tests := []struct {
		name              string
		target            string
		rootDir           string
		artifactOpt       artifact.Option
		scannerOpt        misconf.ScannerOption
		disabledAnalyzers []analyzer.Type
		disabledHandlers  []types.HandlerType
		wantBlobs         []cachetest.WantBlob
		want              artifact.Reference
		wantErr           string
	}{
		{
			name:    "happy path for raw image",
			target:  "testdata/mock.img",
			rootDir: "testdata/alpine",
			wantBlobs: []cachetest.WantBlob{
				{
					ID:       "sha256:84a726d23c36d0e1857101969b257c1199de5432489d44581750d54ea8eff8cd",
					BlobInfo: expectedBlobInfo,
				},
			},
			want: artifact.Reference{
				Name: "rawdata.img",
				Type: types.TypeVM,
				ID:   "sha256:84a726d23c36d0e1857101969b257c1199de5432489d44581750d54ea8eff8cd",
				BlobIDs: []string{
					"sha256:84a726d23c36d0e1857101969b257c1199de5432489d44581750d54ea8eff8cd",
				},
			},
		},
		{
			name:    "happy path for ebs",
			target:  "ebs:ebs-012345",
			rootDir: "testdata/alpine",
			wantBlobs: []cachetest.WantBlob{
				{
					ID:       "sha256:c28da2df41e019b5d18459440178341ec05e9082b12b6f11afe73f0600bfe96a",
					BlobInfo: expectedBlobInfo,
				},
			},
			want: artifact.Reference{
				Name: "ebs-012345",
				Type: types.TypeVM,
				ID:   "sha256:c28da2df41e019b5d18459440178341ec05e9082b12b6f11afe73f0600bfe96a",
				BlobIDs: []string{
					"sha256:c28da2df41e019b5d18459440178341ec05e9082b12b6f11afe73f0600bfe96a",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cachetest.NewCache(t, nil)

			m := &mockWalker{root: tt.rootDir}

			a, err := vm.NewArtifact(tt.target, c, m, tt.artifactOpt)
			require.NoError(t, err)

			if aa, ok := a.(*vm.EBS); ok {
				ebs := ebsfile.NewMockEBS("testdata/mock.img", 1, 2)
				aa.SetEBS(ebs)
			}

			got, err := a.Inspect(t.Context())
			defer a.Clean(got)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			tt.want.Name = trimPrefix(tt.target)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			cachetest.AssertBlobs(t, c, tt.wantBlobs)
		})
	}
}

func trimPrefix(s string) string {
	s = strings.TrimPrefix(s, ebsPrefix)
	s = strings.TrimPrefix(s, filePrefix)
	return s
}

var expectedBlobInfo = types.BlobInfo{
	SchemaVersion: types.BlobJSONSchemaVersion,
	OS: types.OS{
		Family: "alpine",
		Name:   "3.17.5",
	},
	PackageInfos: []types.PackageInfo{
		{
			FilePath: "lib/apk/db/installed",
			Packages: types.Packages{
				{
					ID:         "musl@1.2.3-r5",
					Name:       "musl",
					Version:    "1.2.3-r5",
					SrcName:    "musl",
					SrcVersion: "1.2.3-r5",
					Licenses:   []string{"MIT"},
					Arch:       "aarch64",
					Digest:     "sha1:742b0a26f327c6da60d42a02c3eb6189a58e468f",
					InstalledFiles: []string{
						"lib/ld-musl-aarch64.so.1",
						"lib/libc.musl-aarch64.so.1",
					},
				},
			},
		},
	},
}
