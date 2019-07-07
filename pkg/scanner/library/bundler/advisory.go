package bundler

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/etcd-io/bbolt"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

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
	Ghsa               string
	Title              string
	Url                string
	Description        string
	CvssV2             float64  `yaml:"cvss_v2"`
	CvssV3             float64  `yaml:"cvss_v3"`
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
	s.db, err = s.walk()
	return err
}

func (s *Scanner) walk() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	root := filepath.Join(repoPath, "gems")

	var vulns []vulnerability.Vulnerability
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

		// for detecting vulnerabilities
		advisories, ok := advisoryDB[advisory.Gem]
		if !ok {
			advisories = []Advisory{}
		}
		advisoryDB[advisory.Gem] = append(advisories, advisory)

		// for displaying vulnerability detail
		var vulnerabilityID string
		if advisory.Cve != "" {
			vulnerabilityID = fmt.Sprintf("CVE-%s", advisory.Cve)
		} else if advisory.Osvdb != "" {
			vulnerabilityID = fmt.Sprintf("OSVDB-%s", advisory.Osvdb)
		} else if advisory.Ghsa != "" {
			vulnerabilityID = fmt.Sprintf("GHSA-%s", advisory.Ghsa)
		} else {
			return nil
		}

		vulns = append(vulns, vulnerability.Vulnerability{
			ID:          vulnerabilityID,
			CvssScore:   advisory.CvssV2,
			CvssScoreV3: advisory.CvssV3,
			References:  append([]string{advisory.Url}, advisory.Related.Url...),
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
			if err := db.Put(b, vuln.ID, vulnerability.RubySec, vuln); err != nil {
				return xerrors.Errorf("failed to save %s vulnerability: %w", s.Type(), err)
			}
		}
		return nil
	})
}
