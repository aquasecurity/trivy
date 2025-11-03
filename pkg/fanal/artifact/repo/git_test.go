//go:build unix

package repo

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
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
	ts := gittest.NewTestServer(t, gittest.Options{})
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
			assertion: func(t assert.TestingT, err error, _ ...any) bool {
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
			assertion: func(t assert.TestingT, err error, _ ...any) bool {
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
			assertion: func(t assert.TestingT, err error, _ ...any) bool {
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
			assertion: func(t assert.TestingT, err error, _ ...any) bool {
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
			assertion: func(t assert.TestingT, err error, _ ...any) bool {
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
	ts := gittest.NewTestServer(t, gittest.Options{})
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
				Type: types.TypeRepository,
				ID:   "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				BlobIDs: []string{
					"sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				},
				RepoMetadata: artifact.RepoMetadata{
					RepoURL:   ts.URL + "/test-repo.git",
					Branch:    "main",
					Tags:      []string{"v0.0.1"},
					Commit:    "8a19b492a589955c3e70c6ad8efd1e4ec6ae0d35",
					CommitMsg: "Update README.md",
					Author:    "Teppei Fukuda <knqyf263@gmail.com>",
					Committer: "GitHub <noreply@github.com>",
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
				Type: types.TypeRepository,
				ID:   "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				BlobIDs: []string{
					"sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c", // Calculated from commit hash
				},
				RepoMetadata: artifact.RepoMetadata{
					RepoURL:   "https://github.com/aquasecurity/trivy-test-repo/",
					Branch:    "main",
					Tags:      []string{"v0.0.1"},
					Commit:    "8a19b492a589955c3e70c6ad8efd1e4ec6ae0d35",
					CommitMsg: "Update README.md",
					Author:    "Teppei Fukuda <knqyf263@gmail.com>",
					Committer: "GitHub <noreply@github.com>",
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
				require.NoError(t, os.WriteFile(filepath.Join(dir, "new-file.txt"), []byte("test"), 0o644))
				t.Cleanup(func() {
					require.NoError(t, os.Remove(filepath.Join(dir, "new-file.txt")))
				})
			},
			want: artifact.Reference{
				Name: "../../../../internal/gittest/testdata/test-repo",
				Type: types.TypeRepository,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
				RepoMetadata: artifact.RepoMetadata{
					RepoURL:   "https://github.com/aquasecurity/trivy-test-repo/",
					Branch:    "main",
					Tags:      []string{"v0.0.1"},
					Commit:    "8a19b492a589955c3e70c6ad8efd1e4ec6ae0d35",
					CommitMsg: "Update README.md",
					Author:    "Teppei Fukuda <knqyf263@gmail.com>",
					Committer: "GitHub <noreply@github.com>",
				},
			},
			wantBlobInfo: &types.BlobInfo{
				SchemaVersion: types.BlobJSONSchemaVersion,
			},
		},
		{
			name:   "cache hit",
			rawurl: "../../../../internal/gittest/testdata/test-repo",
			setup: func(t *testing.T, _ string, c cache.ArtifactCache) {
				blobInfo := types.BlobInfo{
					SchemaVersion: types.BlobJSONSchemaVersion,
					OS: types.OS{
						Family: types.Alpine,
						Name:   "3.16.0",
					},
				}
				// Store the blob info in the cache to test cache hit
				cacheKey := "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c"
				err := c.PutBlob(t.Context(), cacheKey, blobInfo)
				require.NoError(t, err)
			},
			want: artifact.Reference{
				Name: "../../../../internal/gittest/testdata/test-repo",
				Type: types.TypeRepository,
				ID:   "sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c",
				BlobIDs: []string{
					"sha256:dc7c6039424c9fce969d3c2972d261af442a33f13e7494464386dbe280612d4c",
				},
				RepoMetadata: artifact.RepoMetadata{
					RepoURL:   "https://github.com/aquasecurity/trivy-test-repo/",
					Branch:    "main",
					Tags:      []string{"v0.0.1"},
					Commit:    "8a19b492a589955c3e70c6ad8efd1e4ec6ae0d35",
					CommitMsg: "Update README.md",
					Author:    "Teppei Fukuda <knqyf263@gmail.com>",
					Committer: "GitHub <noreply@github.com>",
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

			ref, err := art.Inspect(t.Context())
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, ref)

			// Verify cache contents after inspection
			blobInfo, err := c.GetBlob(t.Context(), tt.want.BlobIDs[0])
			require.NoError(t, err)
			assert.Equal(t, tt.wantBlobInfo, &blobInfo, "cache content mismatch")
		})
	}
}

// setupAuthTestServer creates a test server with authentication and returns parsed URL with /test-repo.git path
func setupAuthTestServer(t *testing.T, username, password string) *url.URL {
	t.Helper()
	ts := gittest.NewTestServer(t, gittest.Options{
		Username: username,
		Password: password,
	})
	t.Cleanup(ts.Close)

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)
	tsURL.Path = "/test-repo.git"

	return tsURL
}

// testInspectArtifact is a helper function to inspect an artifact and assert the results
func testInspectArtifact(t *testing.T, target, wantRepoURL, wantErr string) {
	t.Helper()
	art, cleanup, err := NewArtifact(target, cache.NewMemoryCache(), walker.NewFS(), artifact.Option{})
	t.Cleanup(cleanup)

	if wantErr != "" {
		require.ErrorContains(t, err, wantErr)
		return
	}
	require.NoError(t, err)

	// Verify Inspect works
	ref, err := art.Inspect(t.Context())
	require.NoError(t, err)

	// Verify the RepoURL
	assert.Equal(t, wantRepoURL, ref.RepoMetadata.RepoURL)

	// Verify we have blob IDs (indicating successful scan)
	assert.NotEmpty(t, ref.BlobIDs)
}

func TestArtifact_InspectWithAuth(t *testing.T) {
	const (
		testUsername = "testuser"
		testPassword = "testpass"
	)

	// Test with environment variable authentication (GITHUB_TOKEN, GITLAB_TOKEN)
	t.Run("environment variable authentication", func(t *testing.T) {
		const testGitUsername = "fanal-aquasecurity-scan" // This is the username used by Trivy

		// Setup test server with authentication
		tsURL := setupAuthTestServer(t, testGitUsername, testPassword)

		tests := []struct {
			name        string
			target      string
			envVars     map[string]string
			wantErr     string
			wantRepoURL string
		}{
			{
				name:   "success with GITHUB_TOKEN",
				target: tsURL.String(),
				envVars: map[string]string{
					"GITHUB_TOKEN": testPassword,
				},
				wantRepoURL: tsURL.String(),
			},
			{
				name:   "success with GITLAB_TOKEN",
				target: tsURL.String(),
				envVars: map[string]string{
					"GITLAB_TOKEN": testPassword,
				},
				wantRepoURL: tsURL.String(),
			},
			{
				name:    "failure without token",
				target:  tsURL.String(),
				wantErr: "authentication required",
			},
			{
				name:   "failure with wrong token",
				target: tsURL.String(),
				envVars: map[string]string{
					"GITHUB_TOKEN": "wrongpassword",
				},
				wantErr: "authentication required",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Set test environment variables
				for key, value := range tt.envVars {
					t.Setenv(key, value)
				}

				// Test using helper function
				testInspectArtifact(t, tt.target, tt.wantRepoURL, tt.wantErr)
			})
		}
	})

	// Test with URL-embedded authentication
	t.Run("URL embedded authentication", func(t *testing.T) {
		// Setup test server with authentication
		tsURL := setupAuthTestServer(t, testUsername, testPassword)

		// Helper function to generate target URL with credentials
		makeTarget := func(username, password string) string {
			u := *tsURL // Copy the URL
			if username != "" && password != "" {
				u.User = url.UserPassword(username, password)
			}
			return u.String()
		}

		tests := []struct {
			name        string
			target      string
			wantRepoURL string
			wantErr     string
		}{
			{
				name:        "success with embedded credentials",
				target:      makeTarget(testUsername, testPassword),
				wantRepoURL: tsURL.String(),
			},
			{
				name:    "failure with wrong password",
				target:  makeTarget(testUsername, "wrongpass"),
				wantErr: "authentication required",
			},
			{
				name:    "failure without credentials",
				target:  makeTarget("", ""),
				wantErr: "authentication required",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Test using helper function
				testInspectArtifact(t, tt.target, tt.wantRepoURL, tt.wantErr)
			})
		}
	})

	// Test cloning with embedded credentials and then scanning the local directory
	t.Run("clone with credentials then scan local", func(t *testing.T) {
		// Setup test server with authentication
		tsURL := setupAuthTestServer(t, testUsername, testPassword)

		// Add credentials to URL
		u := *tsURL // Copy the URL
		u.User = url.UserPassword(testUsername, testPassword)
		targetWithCreds := u.String()

		// Clone the repository with URL-embedded credentials
		cloneDir := filepath.Join(t.TempDir(), "cloned-repo")

		// Use go-git directly to clone with URL-embedded credentials
		_, err := git.PlainClone(cloneDir, false, &git.CloneOptions{
			URL: targetWithCreds,
		})
		require.NoError(t, err)

		// Scan and verify the local cloned directory
		testInspectArtifact(t, cloneDir, tsURL.String(), "")
	})
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
