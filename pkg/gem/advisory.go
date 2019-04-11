package gem

import (
	"io/ioutil"
	"os"
	"path/filepath"

	git "gopkg.in/src-d/go-git.v4"
	yaml "gopkg.in/yaml.v2"
)

type AdvisoryDB map[string][]Advisory

var (
	repoPath = "/tmp/foo"
)

type Advisory struct {
	Gem                string
	Cve                string
	Url                string
	PatchedVersions    []string `yaml:"patched_versions"`
	UnaffectedVersions []string `yaml:"unaffected_versions"`
	Related            Related
}

type Related struct {
	Cve []string
	Url []string
}

func UpdateDB() (AdvisoryDB, error) {
	_, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		URL:      "https://github.com/rubysec/ruby-advisory-db.git",
		Progress: os.Stdout,
	})
	if err != nil && err != git.ErrRepositoryAlreadyExists {
		return nil, err
	}
	if err = pull(); err != nil {
		return nil, err
	}
	return walk()
}

func pull() error {
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

	// Print the latest commit that was just pulled
	//ref, err := r.Head()
	//pp.Println(ref)
	return nil
}

func walk() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	root := filepath.Join(repoPath, "gems")

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		advisory := Advisory{}
		err = yaml.Unmarshal(buf, &advisory)
		if err != nil {
			return err
		}

		advisories, ok := advisoryDB[advisory.Gem]
		if !ok {
			advisories = []Advisory{}
		}
		advisoryDB[advisory.Gem] = append(advisories, advisory)

		return nil
	})
	if err != nil {
		return nil, err
	}
	return advisoryDB, nil
}
