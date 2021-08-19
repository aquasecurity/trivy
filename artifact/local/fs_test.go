package local

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/all"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		scannerOpt         config.ScannerOption
		disabledAnalyzers  []analyzer.Type
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               types.ArtifactReference
		wantErr            string
	}{
		{
			name: "happy path",
			fields: fields{
				dir: "./testdata",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:fb5174f05302bcc3bfd2d622cfd27430ab237693fbdcaf1ce18bb2162e2ab1de",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:0f88c2f4a441514ebd105e81527af76af15bed17d91c17ba3637397f8c4f1925",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:fb5174f05302bcc3bfd2d622cfd27430ab237693fbdcaf1ce18bb2162e2ab1de",
				BlobIDs: []string{
					"sha256:fb5174f05302bcc3bfd2d622cfd27430ab237693fbdcaf1ce18bb2162e2ab1de",
				},
			},
		},
		{
			name: "disable analyzers",
			fields: fields{
				dir: "./testdata",
			},
			disabledAnalyzers: []analyzer.Type{analyzer.TypeAlpine, analyzer.TypeApk},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:86d30449fe3266668ad009635b0ae28a9279d75f0a79646bf26de174eeac0db7",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:3404e98968ad338dc60ef74c0dd5bdd893478415cd2296b0c265a5650b3ae4d6",
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:86d30449fe3266668ad009635b0ae28a9279d75f0a79646bf26de174eeac0db7",
				BlobIDs: []string{
					"sha256:86d30449fe3266668ad009635b0ae28a9279d75f0a79646bf26de174eeac0db7",
				},
			},
		},
		{
			name: "sad path PutBlob returns an error",
			fields: fields{
				dir: "./testdata",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:fb5174f05302bcc3bfd2d622cfd27430ab237693fbdcaf1ce18bb2162e2ab1de",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:0f88c2f4a441514ebd105e81527af76af15bed17d91c17ba3637397f8c4f1925",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to store blob",
		},
		{
			name: "sad path with no such directory",
			fields: fields{
				dir: "./testdata/unknown",
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			a, err := NewArtifact(tt.fields.dir, c, tt.disabledAnalyzers, tt.scannerOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
