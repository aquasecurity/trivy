package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/knqyf263/trivy/pkg/utils"

	"github.com/knqyf263/trivy/pkg/git"
)

const (
	dbURL = "https://github.com/nodejs/security-wg.git"
)

var (
	repoPath = filepath.Join(utils.CacheDir(), "nodejs-security-wg")
)

type AdvisoryDB map[string][]Advisory

type Advisory struct {
	ID                 int
	Title              string
	ModuleName         string `json:"module_name""`
	Cves               []string
	VulnerableVersions string `json:"vulnerable_versions"`
	PatchedVersions    string `json:"patched_versions"`
	Recommendation     string
	References         []string
	CvssScoreNumber    json.Number `json:"cvss_score"`
	CvssScore          float64
}

func (s *Scanner) UpdateDB() (err error) {
	if _, err := git.CloneOrPull(dbURL, repoPath); err != nil {
		return err
	}
	s.db, err = walk()
	return err
}

func walk() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	err := filepath.Walk(filepath.Join(repoPath, "vuln"), func(path string, info os.FileInfo, err error) error {
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

		advisories, ok := advisoryDB[advisory.ModuleName]
		if !ok {
			advisories = []Advisory{}
		}
		advisoryDB[advisory.ModuleName] = append(advisories, advisory)

		return nil
	})
	if err != nil {
		return nil, err
	}
	return advisoryDB, nil
}
