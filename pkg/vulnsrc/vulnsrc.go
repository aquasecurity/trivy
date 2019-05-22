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
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const (
	repoURL = "https://github.com/knqyf263/vuln-list.git"
)

type updateFunc func(dir string, updatedFiles map[string]struct{}) error

var updateMap = map[string]updateFunc{
	vulnerability.Nvd:        nvd.Update,
	vulnerability.Alpine:     alpine.Update,
	vulnerability.RedHat:     redhat.Update,
	vulnerability.Debian:     debian.Update,
	vulnerability.DebianOVAL: debianoval.Update,
	vulnerability.Ubuntu:     ubuntu.Update,
}

func Update(names []string) error {
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

	for _, distribution := range names {
		updateFunc, ok := updateMap[distribution]
		if !ok {
			return xerrors.Errorf("%s does not supported yet", distribution)
		}
		log.Logger.Infof("Updating %s data...", distribution)
		if err := updateFunc(dir, updatedFiles); err != nil {
			return xerrors.Errorf("error in %s update: %w", distribution, err)
		}
	}
	return nil
}
