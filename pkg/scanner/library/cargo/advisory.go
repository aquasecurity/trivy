package cargo

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/etcd-io/bbolt"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/git"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	dbURL = "https://github.com/RustSec/advisory-db.git"
)

var (
	repoPath string
)

type AdvisoryDB map[string][]Lockfile

type Lockfile struct {
	Advisory `toml:"advisory"`
}

type Advisory struct {
	Id                string
	Package           string
	Title             string `toml:"title"`
	Url               string
	Date              string
	Description       string
	Keywords          []string
	PatchedVersions   []string `toml:"patched_versions"`
	AffectedFunctions []string `toml:"affected_functions"`
}

func (s *Scanner) UpdateDB() (err error) {
	repoPath = filepath.Join(utils.CacheDir(), "rust-advisory-db")
	if _, err := git.CloneOrPull(dbURL, repoPath); err != nil {
		return xerrors.Errorf("error in %s security DB update: %w", s.Type(), err)
	}
	s.db, err = s.walk()
	return err
}

func (s *Scanner) walk() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	root := filepath.Join(repoPath, "crates")

	var vulns []vulnerability.Vulnerability
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return xerrors.Errorf("failed to read a file: %w", err)
		}

		advisory := Lockfile{}
		err = toml.Unmarshal(buf, &advisory)
		if err != nil {
			return xerrors.Errorf("failed to unmarshal TOML: %w", err)
		}

		// for detecting vulnerabilities
		advisories, ok := advisoryDB[advisory.Package]
		if !ok {
			advisories = []Lockfile{}
		}
		advisoryDB[advisory.Package] = append(advisories, advisory)

		// for displaying vulnerability detail
		vulns = append(vulns, vulnerability.Vulnerability{
			ID:          advisory.Id,
			References:  []string{advisory.Url},
			Title:       advisory.Title,
			Description: advisory.Description,
		})

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in file walk: %w", err)
	}

	if err = s.saveVulnerabilities(vulns); err != nil {
		return nil, err
	}
	return advisoryDB, nil
}

func (s *Scanner) saveVulnerabilities(vulns []vulnerability.Vulnerability) error {
	return vulnerability.BatchUpdate(func(b *bbolt.Bucket) error {
		for _, vuln := range vulns {
			if err := db.Put(b, vuln.ID, vulnerability.RustSec, vuln); err != nil {
				return xerrors.Errorf("failed to save %s vulnerability: %w", s.Type(), err)
			}
		}
		return nil
	})
}
