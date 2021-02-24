package local

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
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
					BlobID: "sha256:e1fee9054eea6ee450a2a3f2b0e49117a70e3a0968ac43ff90caf977e6ee71f4",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						AnalyzerVersions: map[string]int{
							string(analyzer.TypeAlpine): 1,
							string(analyzer.TypeApk):    1,
						},
						DiffID: "sha256:e1fee9054eea6ee450a2a3f2b0e49117a70e3a0968ac43ff90caf977e6ee71f4",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				ID:   "sha256:e1fee9054eea6ee450a2a3f2b0e49117a70e3a0968ac43ff90caf977e6ee71f4",
				BlobIDs: []string{
					"sha256:e1fee9054eea6ee450a2a3f2b0e49117a70e3a0968ac43ff90caf977e6ee71f4",
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
					BlobID: "sha256:3404e98968ad338dc60ef74c0dd5bdd893478415cd2296b0c265a5650b3ae4d6",
					BlobInfo: types.BlobInfo{
						SchemaVersion:    types.BlobJSONSchemaVersion,
						AnalyzerVersions: map[string]int{},
						DiffID:           "sha256:3404e98968ad338dc60ef74c0dd5bdd893478415cd2296b0c265a5650b3ae4d6",
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				ID:   "sha256:3404e98968ad338dc60ef74c0dd5bdd893478415cd2296b0c265a5650b3ae4d6",
				BlobIDs: []string{
					"sha256:3404e98968ad338dc60ef74c0dd5bdd893478415cd2296b0c265a5650b3ae4d6",
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
					BlobID: "sha256:e1fee9054eea6ee450a2a3f2b0e49117a70e3a0968ac43ff90caf977e6ee71f4",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						AnalyzerVersions: map[string]int{
							string(analyzer.TypeAlpine): 1,
							string(analyzer.TypeApk):    1,
						},
						DiffID: "sha256:e1fee9054eea6ee450a2a3f2b0e49117a70e3a0968ac43ff90caf977e6ee71f4",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
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

			a := NewArtifact(tt.fields.dir, c, tt.disabledAnalyzers)
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
