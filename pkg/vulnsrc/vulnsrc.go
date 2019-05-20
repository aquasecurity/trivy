package vulnsrc

import (
	"path/filepath"

	"github.com/knqyf263/trivy/pkg/git"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/alpine"
	"github.com/knqyf263/trivy/pkg/vulnsrc/debian"
	debianoval "github.com/knqyf263/trivy/pkg/vulnsrc/debian-oval"
	"github.com/knqyf263/trivy/pkg/vulnsrc/nvd"
	"github.com/knqyf263/trivy/pkg/vulnsrc/redhat"
	"github.com/knqyf263/trivy/pkg/vulnsrc/ubuntu"
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
		return xerrors.Errorf("error in vulnsrc clone or pull: %w", err)
	}
	log.Logger.Debugf("total updated files: %d", len(updatedFiles))

	// Only last_updated.json
	if len(updatedFiles) <= 1 {
		return nil
	}

	// Update NVD
	log.Logger.Info("Updating NVD data...")
	if err = nvd.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in NVD update: %w", err)
	}

	// Update Alpine OVAL
	log.Logger.Info("Updating Alpine data...")
	if err = alpine.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in Alpine OVAL update: %w", err)
	}

	// Update RedHat
	log.Logger.Info("Updating RedHat data...")
	if err = redhat.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in RedHat update: %w", err)
	}

	// Update Debian
	log.Logger.Info("Updating Debian data...")
	if err = debian.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in Debian update: %w", err)
	}

	// Update Debian OVAL
	log.Logger.Info("Updating Debian OVAL data...")
	if err = debianoval.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in Debian OVAL update: %w", err)
	}

	// Update Ubuntu
	log.Logger.Info("Updating Ubuntu data...")
	if err = ubuntu.Update(dir, updatedFiles); err != nil {
		return xerrors.Errorf("error in Ubuntu update: %w", err)
	}

	return nil
}
