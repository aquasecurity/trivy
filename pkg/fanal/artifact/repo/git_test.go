//go:build unix

package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/gittest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/uuid"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
)

func TestNewArtifact(t *testing.T) {
	ts := gittest.NewTestServer(t)
	defer ts.Close()

	type args struct {
		target     string
		c          cache.ArtifactCache
		noProgress bool
		repoBranch string
		repoTag    string
		repoCommit string
	}
	tests := []struct {
		name      string
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{
			name: "remote repo",
			args: args{
				target:     ts.URL + "/test-repo.git",
				c:          nil,
				noProgress: false,
			},
			assertion: assert.NoError,
		},
		{
			name: "local repo",
			args: args{
				target:     "../../../../internal/gittest/testdata/test-repo",
				c:          nil,
				noProgress: false,
			},
			assertion: assert.NoError,
		},
		{
			name: "no progress",
			args: args{
				target:     ts.URL + "/test-repo.git",
				c:          nil,
				noProgress: true,
			},
			assertion: assert.NoError,
		},
		{
			name: "branch",
			args: args{
				target:     ts.URL + "/test-repo.git",
				c:          nil,
				repoBranch: "valid-branch",
			},
			assertion: assert.NoError,
		},
		{
			name: "tag",
			args: args{
				target:  ts.URL + "/test-repo.git",
				c:       nil,
				repoTag: "v0.0.1",
			},
			assertion: assert.NoError,
		},
		{
			name: "commit",
			args: args{
				target:     ts.URL + "/test-repo.git",
				c:          nil,
				repoCommit: "8a19b492a589955c3e70c6ad8efd1e4ec6ae0d35",
			},
			assertion: assert.NoError,
		},
		{
			name: "sad path",
			args: args{
				target:     ts.URL + "/unknown.git",
				c:          nil,
				noProgress: false,
			},
			assertion: func(t assert.TestingT, err error, args ...any) bool {
				return assert.ErrorContains(t, err, "repository not found")
			},
		},
		{
			name: "invalid url",
			args: args{
				target:     "ht tp://foo.com",
				c:          nil,
				noProgress: false,
			},
			assertion: func(t assert.TestingT, err error, args ...any) bool {
				return assert.ErrorContains(t, err, "url parse error")
			},
		},
		{
			name: "invalid branch",
			args: args{
				target:     ts.URL + "/test-repo.git",
				c:          nil,
				repoBranch: "invalid-branch",
			},
			assertion: func(t assert.TestingT, err error, args ...any) bool {
				return assert.ErrorContains(t, err, `couldn't find remote ref "refs/heads/invalid-branch"`)
			},
		},
		{
			name: "invalid tag",
			args: args{
				target:  ts.URL + "/test-repo.git",
				c:       nil,
				repoTag: "v1.0.9",
			},
			assertion: func(t assert.TestingT, err error, args ...any) bool {
				return assert.ErrorContains(t, err, `couldn't find remote ref "refs/tags/v1.0.9"`)
			},
		},
		{
			name: "invalid commit",
			args: args{
				target:     ts.URL + "/test-repo.git",
				c:          nil,
				repoCommit: "6ac152fe2b87cb5e243414df71790a32912e778e",
			},
			assertion: func(t assert.TestingT, err error, args ...any) bool {
				return assert.ErrorContains(t, err, "git checkout error: object not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup, err := NewArtifact(tt.args.target, tt.args.c, walker.NewFS(), artifact.Option{
				NoProgress: tt.args.noProgress,
				RepoBranch: tt.args.repoBranch,
				RepoTag:    tt.args.repoTag,
				RepoCommit: tt.args.repoCommit,
			})
			tt.assertion(t, err)
			defer cleanup()
		})
	}
}

func TestArtifact_Inspect(t *testing.T) {
	ts := gittest.NewTestServer(t)
	defer ts.Close()

	tests := []struct {
		name         string
		rawurl       string
		setup        func(t *testing.T, dir string, c cache.ArtifactCache)
		want         artifact.Reference
		wantBlobInfo *types.BlobInfo
		wantErr      bool
	}{
		{
			name:   "remote repo",
			rawurl: ts.URL + "/test-repo.git",
			want: artifact.Reference{
				Name: ts.URL + "/test-repo.git",
				Type: artifact.TypeRepository,
				ID:   "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				BlobIDs: []string{
					"sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				},
			},
			wantBlobInfo: &types.BlobInfo{
				SchemaVersion: types.BlobJSONSchemaVersion,
			},
		},
		{
			name:   "local repo",
			rawurl: "../../../../internal/gittest/testdata/test-repo",
			want: artifact.Reference{
				Name: "../../../../internal/gittest/testdata/test-repo",
				Type: artifact.TypeRepository,
				ID:   "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				BlobIDs: []string{
					"sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				},
			},
			wantBlobInfo: &types.BlobInfo{
				SchemaVersion: types.BlobJSONSchemaVersion,
			},
		},
		{
			name:   "dirty repository",
			rawurl: "../../../../internal/gittest/testdata/test-repo",
			setup: func(t *testing.T, dir string, _ cache.ArtifactCache) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "new-file.txt"), []byte("test"), 0644))
				t.Cleanup(func() {
					require.NoError(t, os.Remove(filepath.Join(dir, "new-file.txt")))
				})
			},
			want: artifact.Reference{
				Name: "../../../../internal/gittest/testdata/test-repo",
				Type: artifact.TypeRepository,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
			wantBlobInfo: &types.BlobInfo{
				SchemaVersion: types.BlobJSONSchemaVersion,
			},
		},
		{
			name:   "cache hit",
			rawurl: "../../../../internal/gittest/testdata/test-repo",
			setup: func(t *testing.T, dir string, c cache.ArtifactCache) {
				blobInfo := types.BlobInfo{
					SchemaVersion: types.BlobJSONSchemaVersion,
					OS: types.OS{
						Family: types.Alpine,
						Name:   "3.16.0",
					},
				}
				// Store the blob info in the cache to test cache hit
				cacheKey := "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c"
				err := c.PutBlob(cacheKey, blobInfo)
				require.NoError(t, err)
			},
			want: artifact.Reference{
				Name: "../../../../internal/gittest/testdata/test-repo",
				Type: artifact.TypeRepository,
				ID:   "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c",
				BlobIDs: []string{
					"sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c",
				},
			},
			wantBlobInfo: &types.BlobInfo{
				SchemaVersion: types.BlobJSONSchemaVersion,
				OS: types.OS{
					Family: types.Alpine,
					Name:   "3.16.0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistency
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			// Create memory cache
			c := cache.NewMemoryCache()

			// Apply setup if specified
			if tt.setup != nil {
				tt.setup(t, tt.rawurl, c)
			}

			art, cleanup, err := NewArtifact(tt.rawurl, c, walker.NewFS(), artifact.Option{})
			require.NoError(t, err)
			defer cleanup()

			ref, err := art.Inspect(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, ref)

			// Verify cache contents after inspection
			blobInfo, err := c.GetBlob(tt.want.BlobIDs[0])
			require.NoError(t, err)
			assert.Equal(t, tt.wantBlobInfo, &blobInfo, "cache content mismatch")
		})
	}
}

func Test_newURL(t *testing.T) {
	type args struct {
		rawurl string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				rawurl: "https://github.com/aquasecurity/fanal",
			},
			want: "https://github.com/aquasecurity/fanal",
		},
		{
			name: "happy path: no scheme",
			args: args{
				rawurl: "github.com/aquasecurity/fanal",
			},
			want: "https://github.com/aquasecurity/fanal",
		},
		{
			name: "sad path: invalid url",
			args: args{
				rawurl: "ht tp://foo.com",
			},
			wantErr: "first path segment in URL cannot contain colon",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newURL(tt.args.rawurl)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
