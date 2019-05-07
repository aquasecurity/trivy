package bundler

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/git"
	"github.com/knqyf263/trivy/pkg/utils"
	"gopkg.in/yaml.v2"
)

const (
	dbURL = "https://github.com/rubysec/ruby-advisory-db.git"
)

var (
	repoPath = filepath.Join(utils.CacheDir(), "ruby-advisory-db")
)

type AdvisoryDB map[string][]Advisory

type Advisory struct {
	Gem                string
	Cve                string
	Osvdb              string
	Title              string
	Url                string
	PatchedVersions    []string `yaml:"patched_versions"`
	UnaffectedVersions []string `yaml:"unaffected_versions"`
	Related            Related
}

type Related struct {
	Cve []string
	Url []string
}

func (s *Scanner) UpdateDB() (err error) {
	if _, err := git.CloneOrPull(dbURL, repoPath); err != nil {
		return xerrors.Errorf("error in %s security DB update: %w", s.Type(), err)
	}
	s.db, err = walk()
	return err
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
			return xerrors.Errorf("failed to read a file: %w", err)
		}

		advisory := Advisory{}
		err = yaml.Unmarshal(buf, &advisory)
		if err != nil {
			return xerrors.Errorf("failed to unmarshal YAML: %w", err)
		}

		advisories, ok := advisoryDB[advisory.Gem]
		if !ok {
			advisories = []Advisory{}
		}
		advisoryDB[advisory.Gem] = append(advisories, advisory)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in file wakl: %w", err)
	}
	return advisoryDB, nil
}
