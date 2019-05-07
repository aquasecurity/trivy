package pipenv

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/etcd-io/bbolt"

	"github.com/knqyf263/trivy/pkg/db"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/git"
)

const (
	dbURL = "https://github.com/pyupio/safety-db.git"
)

var (
	repoPath = filepath.Join(utils.CacheDir(), "python-safety-db")
)

type AdvisoryDB map[string][]Advisory

type Advisory struct {
	ID       string
	Advisory string
	Cve      string
	Specs    []string
	Version  string `json:"v"`
}

func (s *Scanner) UpdateDB() (err error) {
	if _, err := git.CloneOrPull(dbURL, repoPath); err != nil {
		return err
	}
	s.db, err = s.parse()
	if err != nil {
		return xerrors.Errorf("failed to parse python safety-db: %w", err)
	}
	return nil
}

func (s *Scanner) parse() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	f, err := os.Open(filepath.Join(repoPath, "data", "insecure_full.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// for detecting vulnerabilities
	if err = json.NewDecoder(f).Decode(&advisoryDB); err != nil {
		return nil, err
	}

	// for displaying vulnerability detail
	var vulns []vulnerability.Vulnerability
	for _, advisories := range advisoryDB {
		for _, advisory := range advisories {
			vulnerabilityID := advisory.Cve
			if vulnerabilityID == "" {
				vulnerabilityID = advisory.ID
			}
			vulns = append(vulns, vulnerability.Vulnerability{
				ID:    vulnerabilityID,
				Title: advisory.Advisory,
			})
		}
	}
	if err = s.saveVulnerabilities(vulns); err != nil {
		return nil, err
	}

	return advisoryDB, nil
}

func (s Scanner) saveVulnerabilities(vulns []vulnerability.Vulnerability) error {
	return vulnerability.BatchUpdate(func(b *bbolt.Bucket) error {
		for _, vuln := range vulns {
			if err := db.Put(b, vuln.ID, vulnerability.PythonSafetyDB, vuln); err != nil {
				return xerrors.Errorf("failed to save %s vulnerability: %w", s.Type(), err)
			}
		}
		return nil
	})
}
