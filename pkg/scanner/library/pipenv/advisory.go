package pipenv

import (
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/utils"

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
	s.db, err = parse()
	if err != nil {
		return xerrors.Errorf("failed to parse python safety-db: %w", err)
	}
	return nil
}

func parse() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	f, err := os.Open(filepath.Join(repoPath, "data", "insecure_full.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(&advisoryDB); err != nil {
		return nil, err
	}

	return advisoryDB, nil
}
