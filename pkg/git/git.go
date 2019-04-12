package git

import (
	"os"

	"gopkg.in/src-d/go-git.v4"
)

func CloneOrPull(url, repoPath string) error {
	if err := clone(url, repoPath); err != nil {
		return err
	}
	if err := pull(repoPath); err != nil {
		return err
	}
	return nil
}

func clone(url, repoPath string) error {
	_, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		URL:      url,
		Progress: os.Stdout,
	})
	if err != nil && err != git.ErrRepositoryAlreadyExists {
		return err
	}
	return nil
}

func pull(repoPath string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}

	w, err := r.Worktree()
	if err != nil {
		return err
	}

	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return err
	}

	return nil
}
