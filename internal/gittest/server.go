//go:build unix

package gittest

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sosedoff/gitkit"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
)

var signature = &object.Signature{
	Name:  "Test",
	Email: "test@example.com",
	When:  time.Now(),
}

func NewServer(t *testing.T, repo, dir string) *httptest.Server {
	wtDir := t.TempDir()

	// git init
	r, err := git.PlainInit(wtDir, false)
	require.NoError(t, err)

	wt, err := r.Worktree()
	require.NoError(t, err)

	testutil.CopyDir(t, dir, wtDir)

	_, err = wt.Add(".")
	require.NoError(t, err)

	_, err = wt.Commit("initial commit", &git.CommitOptions{
		Author: signature,
	})
	require.NoError(t, err)

	// Create a bare repository
	bareDir := t.TempDir()
	gitDir := filepath.Join(bareDir, repo+".git")
	_, err = git.PlainClone(gitDir, true, &git.CloneOptions{URL: wtDir})
	require.NoError(t, err)

	// Set up a git server
	service := gitkit.New(gitkit.Config{Dir: bareDir})
	err = service.Setup()
	require.NoError(t, err)

	return httptest.NewServer(service)
}

// NewServerWithRepository creates a git server with an existing repository
func NewServerWithRepository(t *testing.T, repo, dir string) *httptest.Server {
	// Create a bare repository
	bareDir := t.TempDir()
	gitDir := filepath.Join(bareDir, repo+".git")

	// Clone the existing repository as a bare repository
	r, err := git.PlainClone(gitDir, true, &git.CloneOptions{
		URL:  dir,
		Tags: git.AllTags,
	})
	require.NoError(t, err)

	// Fetch all remote branches and create local branches
	err = r.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{
			"+refs/remotes/origin/*:refs/heads/*",
		},
		Tags: git.AllTags,
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		require.NoError(t, err)
	}

	// Set up a git server
	service := gitkit.New(gitkit.Config{Dir: bareDir})
	err = service.Setup()
	require.NoError(t, err)

	return httptest.NewServer(service)
}

// NewTestServer creates a git server with the local copy of "github.com/aquasecurity/trivy-test-repo".
// If the test repository doesn't exist, it suggests running 'mage test:unit'.
func NewTestServer(t *testing.T) *httptest.Server {
	_, filePath, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filePath), "testdata", "test-repo")

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		require.Fail(t, "test-repo not found. Please run 'mage test:unit' to set up the test fixtures")
	}

	return NewServerWithRepository(t, "test-repo", dir)
}

func Clone(t *testing.T, ts *httptest.Server, repo, worktree string) *git.Repository {
	cloneOptions := git.CloneOptions{
		URL: ts.URL + "/" + repo + ".git",
	}

	r, err := git.PlainClone(worktree, false, &cloneOptions)
	require.NoError(t, err)

	return r
}

func CommitAll(t *testing.T, r *git.Repository, msg string) {
	w, err := r.Worktree()
	require.NoError(t, err)

	_, err = w.Add(".")
	require.NoError(t, err)

	_, err = w.Commit(msg, &git.CommitOptions{
		Author: signature,
	})
	require.NoError(t, err)
}

func SetTag(t *testing.T, r *git.Repository, tag string) {
	h, err := r.Head()
	require.NoError(t, err)

	t.Logf("git tag -a %s %s -m \"%s\"", tag, h.Hash(), tag)
	_, err = r.CreateTag(tag, h.Hash(), &git.CreateTagOptions{
		Tagger:  signature,
		Message: tag,
	})
	require.NoError(t, err)
}

func PushTags(t *testing.T, r *git.Repository) {
	t.Log("git push --tags")
	err := r.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{"refs/tags/*:refs/tags/*"},
	})

	if err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			return
		}
		require.NoError(t, err)
	}
}

func CreateRemoteBranch(t *testing.T, r *git.Repository, branchName string) {
	wt, err := r.Worktree()
	require.NoError(t, err)

	ref := plumbing.NewBranchReferenceName(branchName)
	err = wt.Checkout(&git.CheckoutOptions{
		Branch: ref,
		Create: true,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, wt.Checkout(&git.CheckoutOptions{}))
	}()

	err = r.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec(ref + ":" + ref)},
	})
	require.NoError(t, err)
}
