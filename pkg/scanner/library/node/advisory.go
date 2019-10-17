package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/etcd-io/bbolt"

	"github.com/aquasecurity/trivy/pkg/db"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy/pkg/git"
)

const (
	dbURL = "https://github.com/nodejs/security-wg.git"
)

var (
	repoPath string
)

type AdvisoryDB map[string][]Advisory

type Advisory struct {
	ID                 int
	Title              string
	ModuleName         string `json:"module_name"`
	Cves               []string
	VulnerableVersions string `json:"vulnerable_versions"`
	PatchedVersions    string `json:"patched_versions"`
	Overview           string
	Recommendation     string
	References         []string
	CvssScoreNumber    json.Number `json:"cvss_score"`
	CvssScore          float64
}

func (s *Scanner) UpdateDB() (err error) {
	repoPath = filepath.Join(utils.CacheDir(), "nodejs-security-wg")
	if _, err := git.CloneOrPull(dbURL, repoPath); err != nil {
		return err
	}
	s.db, err = s.walk()
	return err
}

func (s *Scanner) walk() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	var vulns []vulnerability.Vulnerability
	err := filepath.Walk(filepath.Join(repoPath, "vuln"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		advisory := Advisory{}
		if err = json.NewDecoder(f).Decode(&advisory); err != nil {
			return err
		}
		advisory.ModuleName = strings.ToLower(advisory.ModuleName)

		// `cvss_score` returns float or string like "4.8 (MEDIUM)"
		s := strings.Split(advisory.CvssScoreNumber.String(), " ")
		advisory.CvssScore, err = strconv.ParseFloat(s[0], 64)
		if err != nil {
			advisory.CvssScore = -1
		}

		// for detecting vulnerabilities
		advisories, ok := advisoryDB[advisory.ModuleName]
		if !ok {
			advisories = []Advisory{}
		}
		advisoryDB[advisory.ModuleName] = append(advisories, advisory)

		// for displaying vulnerability detail
		vulnerabilityIDs := advisory.Cves
		if len(vulnerabilityIDs) == 0 {
			vulnerabilityIDs = []string{fmt.Sprintf("NSWG-ECO-%d", advisory.ID)}
		}
		for _, vulnID := range vulnerabilityIDs {
			vulns = append(vulns, vulnerability.Vulnerability{
				ID:          vulnID,
				CvssScore:   advisory.CvssScore,
				References:  advisory.References,
				Title:       advisory.Title,
				Description: advisory.Overview,
			})
		}

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

func (s Scanner) saveVulnerabilities(vulns []vulnerability.Vulnerability) error {
	return vulnerability.BatchUpdate(func(b *bbolt.Bucket) error {
		for _, vuln := range vulns {
			if err := db.Put(b, vuln.ID, vulnerability.NodejsSecurityWg, vuln); err != nil {
				return xerrors.Errorf("failed to save %s vulnerability: %w", s.Type(), err)
			}
		}
		return nil
	})
}
