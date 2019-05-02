package vulnsrc

import (
	"path/filepath"

	"github.com/knqyf263/trivy/pkg/vulnsrc/debian"

	"github.com/knqyf263/trivy/pkg/git"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/vulnsrc/nvd"
	"github.com/knqyf263/trivy/utils"
	"golang.org/x/xerrors"
)

const (
	repoURL = "https://github.com/knqyf263/vuln-list.git"
)

func Update() (err error) {
	log.Logger.Info("Updating vulnerability database...")

	// Clone vuln-list repository
	dir := filepath.Join(utils.CacheDir(), "vuln-list")
	updatedFiles, err := git.CloneOrPull(repoURL, dir)
	if err != nil {
		return xerrors.Errorf("error in vulnsrc clone: %w", err)
	}

	// Only last_updated.txt
	if len(updatedFiles) <= 1 {
		return nil
	}

	// Update NVD
	log.Logger.Info("Updating NVD data...")
	if err = nvd.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in NVD update: %w", err)
	}

	// Update RedHat
	//log.Logger.Info("Updating RedHat data...")
	//if err = redhat.Update(dir, updatedFiles); err != nil {
	//	return xerrors.Errorf("error in RedHat update: %w", err)
	//}

	// Update Debian
	log.Logger.Info("Updating Debian data...")
	if err = debian.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in Debian update: %w", err)
	}

	return nil
}
