package vulnsrc

import (
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/git"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/debian"
	debianoval "github.com/aquasecurity/trivy/pkg/vulnsrc/debian-oval"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/nvd"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/redhat"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const (
	repoURL = "https://github.com/aquasecurity/vuln-list.git"
)

type updateFunc func(dir string, updatedFiles map[string]struct{}) error

var (
	// UpdateList has list of update distributions
	UpdateList []string
	updateMap  = map[string]updateFunc{
		vulnerability.Nvd:        nvd.Update,
		vulnerability.Alpine:     alpine.Update,
		vulnerability.RedHat:     redhat.Update,
		vulnerability.Debian:     debian.Update,
		vulnerability.DebianOVAL: debianoval.Update,
		vulnerability.Ubuntu:     ubuntu.Update,
	}
)

func init() {
	UpdateList = make([]string, 0, len(updateMap))
	for distribution := range updateMap {
		UpdateList = append(UpdateList, distribution)
	}
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
