package local

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/library"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
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
					BlobID: "sha256:5d883ef50a8d41f799cf1cf7d2a59cf65afd56e73909cc52ddd8893598ed2cb8",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:5d883ef50a8d41f799cf1cf7d2a59cf65afd56e73909cc52ddd8893598ed2cb8",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2"},
								},
							},
						},
						Applications: []types.Application{
							{
								Type:     library.Bundler,
								FilePath: "Gemfile.lock",
								Libraries: []types.LibraryInfo{
									{Library: godeptypes.Library{Name: "dotenv", Version: "2.7.2"}},
									{Library: godeptypes.Library{Name: "rack", Version: "2.0.7"}},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				ID:   "sha256:5d883ef50a8d41f799cf1cf7d2a59cf65afd56e73909cc52ddd8893598ed2cb8",
				BlobIDs: []string{
					"sha256:5d883ef50a8d41f799cf1cf7d2a59cf65afd56e73909cc52ddd8893598ed2cb8",
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
					BlobID: "sha256:5d883ef50a8d41f799cf1cf7d2a59cf65afd56e73909cc52ddd8893598ed2cb8",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						DiffID:        "sha256:5d883ef50a8d41f799cf1cf7d2a59cf65afd56e73909cc52ddd8893598ed2cb8",
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "musl", Version: "1.1.24-r2"},
								},
							},
						},
						Applications: []types.Application{
							{
								Type:     library.Bundler,
								FilePath: "Gemfile.lock",
								Libraries: []types.LibraryInfo{
									{Library: godeptypes.Library{Name: "dotenv", Version: "2.7.2"}},
									{Library: godeptypes.Library{Name: "rack", Version: "2.0.7"}},
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

			a := NewArtifact(tt.fields.dir, c)
			got, err := a.Inspect(nil, artifact.InspectOption{SkipDirectories: []string{"testdata/skipdir"}})
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
