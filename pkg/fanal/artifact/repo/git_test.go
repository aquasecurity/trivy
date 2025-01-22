//go:build unix

package repo

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/gittest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/uuid"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
)

func setupGitRepository(t *testing.T, repo, dir string) (*httptest.Server, *git.Repository) {
	gs := gittest.NewServer(t, repo, dir)

	worktree := t.TempDir()
	r := gittest.Clone(t, gs, repo, worktree)

	// Branch
	gittest.CreateRemoteBranch(t, r, "valid-branch")

	// Tag
	gittest.SetTag(t, r, "v1.0.0")
	gittest.PushTags(t, r)

	return gs, r
}

func TestNewArtifact(t *testing.T) {
	ts, repo := setupGitRepository(t, "test-repo", "testdata/test-repo")
	defer ts.Close()

	head, err := repo.Head()
	require.NoError(t, err)

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
				target:     "testdata",
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
				repoTag: "v1.0.0",
			},
			assertion: assert.NoError,
		},
		{
			name: "commit",
			args: args{
				target:     ts.URL + "/test-repo.git",
				c:          nil,
				repoCommit: head.String(),
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
	ts, repo := setupGitRepository(t, "test-repo", "testdata/test-repo")
	defer ts.Close()

	// Get the HEAD commit hash for verification
	head, err := repo.Head()
	require.NoError(t, err)
	commitHash := head.Hash().String()

	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{})
	require.NoError(t, err)

	handlerManager, err := handler.NewManager(artifact.Option{})
	require.NoError(t, err)

	wantCacheKey, err := cache.CalcKey(commitHash, a.AnalyzerVersions(), handlerManager.Versions(), artifact.Option{})
	require.NoError(t, err)

	worktree, err := repo.Worktree()
	require.NoError(t, err)

	localPath := worktree.Filesystem.Root()

	tests := []struct {
		name      string
		rawurl    string
		modifyDir func(t *testing.T, dir string)
		want      artifact.Reference
		wantErr   bool
	}{
		{
			name:   "remote repo",
			rawurl: ts.URL + "/test-repo.git",
			want: artifact.Reference{
				Name: ts.URL + "/test-repo.git",
				Type: artifact.TypeRepository,
				ID:   wantCacheKey, // Calculated from commit hash
				BlobIDs: []string{
					wantCacheKey, // Calculated from commit hash
				},
			},
		},
		{
			name:   "local repo",
			rawurl: localPath,
			want: artifact.Reference{
				Name: localPath,
				Type: artifact.TypeRepository,
				ID:   wantCacheKey, // Calculated from commit hash
				BlobIDs: []string{
					wantCacheKey, // Calculated from commit hash
				},
			},
		},
		{
			name:   "dirty repository",
			rawurl: localPath,
			modifyDir: func(t *testing.T, dir string) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "new-file.txt"), []byte("test"), 0644))
				t.Cleanup(func() {
					require.NoError(t, os.Remove(filepath.Join(dir, "new-file.txt")))
				})
			},
			want: artifact.Reference{
				Name: localPath,
				Type: artifact.TypeRepository,
				ID:   "sha256:88233504639eb201433a0505956309ba0c48156f45beb786f95ccd3e8a343e9d", // Calculated from UUID
				BlobIDs: []string{
					"sha256:88233504639eb201433a0505956309ba0c48156f45beb786f95ccd3e8a343e9d", // Calculated from UUID
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistency
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			// Apply modifications to make the repository dirty if specified
			if tt.modifyDir != nil {
				tt.modifyDir(t, tt.rawurl)
			}

			fsCache, err := cache.NewFSCache(t.TempDir())
			require.NoError(t, err)

			art, cleanup, err := NewArtifact(tt.rawurl, fsCache, walker.NewFS(), artifact.Option{})
			require.NoError(t, err)
			defer cleanup()

			ref, err := art.Inspect(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, ref)
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
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.want, got.String())
		})
	}
}
