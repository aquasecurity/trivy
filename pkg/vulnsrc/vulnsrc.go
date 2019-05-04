package vulnsrc

import (
	"path/filepath"

	"github.com/k0kubun/pp"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/git"
	"github.com/knqyf263/trivy/pkg/log"
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
		return xerrors.Errorf("error in vulnsrc clone or pull: %w", err)
	}

	//filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
	//	if info.IsDir() {
	//		return nil
	//	}
	//	path = strings.TrimPrefix(path, dir+"/")
	//	updatedFiles[path] = struct{}{}
	//	return nil
	//})

	// Only last_updated.txt
	if len(updatedFiles) <= 1 {
		return nil
	}

	//// Update NVD
	//log.Logger.Info("Updating NVD data...")
	//if err = nvd.Update(dir, updatedFiles); err != nil {
	//	return xerrors.Errorf("error in NVD update: %w", err)
	//}
	//
	//// Update Alpine OVAL
	//log.Logger.Info("Updating Alpine data...")
	//if err = alpine.Update(dir, updatedFiles); err != nil {
	//	return xerrors.Errorf("error in Alpine OVAL update: %w", err)
	//}

	// Update RedHat
	//log.Logger.Info("Updating RedHat data...")
	//if err = redhat.Update(dir, updatedFiles); err != nil {
	//	return xerrors.Errorf("error in RedHat update: %w", err)
	//}

	//// Update Debian
	//log.Logger.Info("Updating Debian data...")
	//if err = debian.Update(dir, updatedFiles); err != nil {
	//	return xerrors.Errorf("error in Debian update: %w", err)
	//}
	//
	//// Update Debian OVAL
	//log.Logger.Info("Updating Debian OVAL data...")
	//if err = debianoval.Update(dir, updatedFiles); err != nil {
	//	return xerrors.Errorf("error in Debian OVAL update: %w", err)
	//}

	// Update Ubuntu
	//log.Logger.Info("Updating Ubuntu data...")
	//if err = ubuntu.Update(dir, updatedFiles); err != nil {
	//	return xerrors.Errorf("error in Ubuntu update: %w", err)
	//}

	vuln, _ := vulnerability.Get("CVE-2018-1301")
	pp.Println(vuln)

	return nil
}
