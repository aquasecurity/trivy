package gem

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/knqyf263/trivy/pkg/git"
	"gopkg.in/yaml.v2"
)

type AdvisoryDB map[string][]Advisory

const (
	repoPath = "/tmp/foo"
	dbURL    = "https://github.com/rubysec/ruby-advisory-db.git"
)

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

func (g *Scanner) UpdateDB() (err error) {
	if err := git.CloneOrPull(dbURL, repoPath); err != nil {
		return err
	}
	g.db, err = walk()
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
