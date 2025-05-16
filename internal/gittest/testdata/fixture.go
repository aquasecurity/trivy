package gittest

import (
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
