package gittest

import (
	"errors"
	"log/slog"
	"path/filepath"
	"runtime"

	"github.com/go-git/go-git/v5"
	"github.com/magefile/mage/target"
	"golang.org/x/xerrors"
)

const (
	repoURL = "https://github.com/aquasecurity/trivy-test-repo/"
	repoDir = "test-repo" // subdirectory for the cloned repository
)

// Fixtures clones a Git repository for unit tests
func Fixtures() error {
	_, filePath, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filePath)
	cloneDir := filepath.Join(dir, repoDir)

	// Check if the directory already exists and is up to date
	if updated, err := target.Path(cloneDir, filePath); err != nil {
		return err
	} else if !updated {
		return nil
	}

	// Pull the repository if it already exists
	if repo, err := git.PlainOpen(cloneDir); err == nil {
		slog.Info("Pulling...", slog.String("url", repoURL))
		w, err := repo.Worktree()
		if err != nil {
			return xerrors.Errorf("error getting worktree: %w", err)
		}
		if err = w.Pull(&git.PullOptions{}); err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
			return xerrors.Errorf("error pulling repository: %w", err)
		}
		if err = repo.Fetch(&git.FetchOptions{Tags: git.AllTags}); err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
			return xerrors.Errorf("error fetching tags: %w", err)
		}
		return nil
	}

	slog.Info("Cloning...", slog.String("url", repoURL))

	// Clone the repository with all branches and tags
	_, err := git.PlainClone(cloneDir, false, &git.CloneOptions{
		URL:  repoURL,
		Tags: git.AllTags,
	})
	if err != nil {
		return xerrors.Errorf("error cloning repository: %w", err)
	}

	return nil
}
