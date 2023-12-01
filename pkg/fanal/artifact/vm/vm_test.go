package vm_test

import (
	"context"
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

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/misconf"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/ospkgid"
)

const (
	ebsPrefix  = string(vm.TypeEBS) + ":"
	filePrefix = string(vm.TypeFile) + ":"
)

type mockWalker struct {
	root string
}

func (m *mockWalker) Walk(_ *io.SectionReader, _ string, fn walker.WalkFunc) error {
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
		opener := func() (dio.ReadSeekCloserAt, error) {
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
			wantErr: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, "unsupported type error")
			},
		},
		{
			name:   "sad path file not found",
			target: "testdata/no-file",
			wantErr: func(t assert.TestingT, err error, args ...interface{}) bool {
				return assert.ErrorContains(t, err, "file open error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &mockWalker{root: "testdata"}
			_, err := vm.NewArtifact(tt.target, nil, w, artifact.Option{})
			tt.wantErr(t, err, fmt.Sprintf("NewArtifact(%v, nil, nil)", tt.target))
		})
	}
}

func TestArtifact_Inspect(t *testing.T) {
	tests := []struct {
		name                    string
		target                  string
		rootDir                 string
		artifactOpt             artifact.Option
		scannerOpt              misconf.ScannerOption
		disabledAnalyzers       []analyzer.Type
		disabledHandlers        []types.HandlerType
		missingBlobsExpectation cache.ArtifactCacheMissingBlobsExpectation
		putBlobExpectation      cache.ArtifactCachePutBlobExpectation
		putArtifactExpectations []cache.ArtifactCachePutArtifactExpectation
		want                    types.ArtifactReference
		wantErr                 string
	}{
		{
			name:    "happy path for raw image",
			target:  "testdata/mock.img",
			rootDir: "testdata/alpine",
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID:   "sha256:4d6b9815ae24507b0913bdbe0bdf29f3fc9e20428fe8bd410afa6de9bd149655",
					BlobInfo: expectedBlobInfo,
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:4d6b9815ae24507b0913bdbe0bdf29f3fc9e20428fe8bd410afa6de9bd149655",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "rawdata.img",
				Type: types.ArtifactVM,
				ID:   "sha256:4d6b9815ae24507b0913bdbe0bdf29f3fc9e20428fe8bd410afa6de9bd149655",
				BlobIDs: []string{
					"sha256:4d6b9815ae24507b0913bdbe0bdf29f3fc9e20428fe8bd410afa6de9bd149655",
				},
			},
		},
		{
			name:    "happy path for ebs",
			target:  "ebs:ebs-012345",
			rootDir: "testdata/alpine",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:989d81700cfcdaa3b57456e23fc613da4c72f09ce2ec2f71f83a2b8214761295",
					BlobIDs:    []string{"sha256:989d81700cfcdaa3b57456e23fc613da4c72f09ce2ec2f71f83a2b8214761295"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID:   "sha256:989d81700cfcdaa3b57456e23fc613da4c72f09ce2ec2f71f83a2b8214761295",
					BlobInfo: expectedBlobInfo,
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:989d81700cfcdaa3b57456e23fc613da4c72f09ce2ec2f71f83a2b8214761295",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "ebs-012345",
				Type: types.ArtifactVM,
				ID:   "sha256:989d81700cfcdaa3b57456e23fc613da4c72f09ce2ec2f71f83a2b8214761295",
				BlobIDs: []string{
					"sha256:989d81700cfcdaa3b57456e23fc613da4c72f09ce2ec2f71f83a2b8214761295",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			c.ApplyMissingBlobsExpectation(tt.missingBlobsExpectation)
			c.ApplyPutArtifactExpectations(tt.putArtifactExpectations)
			c.ApplyDeleteBlobsExpectation(cache.ArtifactCacheDeleteBlobsExpectation{
				Args: cache.ArtifactCacheDeleteBlobsArgs{BlobIDsAnything: true},
			})

			m := &mockWalker{root: tt.rootDir}

			a, err := vm.NewArtifact(tt.target, c, m, tt.artifactOpt)
			require.NoError(t, err)

			if aa, ok := a.(*vm.EBS); ok {
				ebs := ebsfile.NewMockEBS("testdata/mock.img", 1, 2)
				aa.SetEBS(ebs)
			}

			got, err := a.Inspect(context.Background())
			defer a.Clean(got)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			tt.want.Name = trimPrefix(tt.target)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
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
					ID:      "musl@1.2.3-r5",
					Name:    "musl",
					Version: "1.2.3-r5",
					Identifier: types.PkgIdentifier{
						PURL: "pkg:apk/alpine/musl@1.2.3-r5?arch=aarch64&distro=3.17.5",
					},
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
