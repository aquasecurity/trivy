package rpm

import (
	"io/ioutil"
	"os"
	"path/filepath"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&rpmPkgAnalyzer{})
}

var requiredFiles = []string{
	"usr/lib/sysimage/rpm/Packages",
	"var/lib/rpm/Packages",
}

type rpmPkgAnalyzer struct{}

func (a rpmPkgAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	parsedPkgs, err := a.parsePkgInfo(content)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("failed to parse rpmdb: %w", err)
	}
	return analyzer.AnalyzeReturn{
		Packages: parsedPkgs,
	}, nil
}

func (a rpmPkgAnalyzer) parsePkgInfo(packageBytes []byte) (pkgs []types.Package, err error) {
	tmpDir, err := ioutil.TempDir("", "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		return nil, xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	filename := filepath.Join(tmpDir, "Packages")
	err = ioutil.WriteFile(filename, packageBytes, 0700)
	if err != nil {
		return nil, xerrors.Errorf("failed to write a package file: %w", err)
	}

	// rpm-python 4.11.3 rpm-4.11.3-35.el7.src.rpm
	// Extract binary package names because RHSA refers to binary package names.
	db, err := rpmdb.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("failed to open RPM DB: %w", err)
	}

	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, xerrors.Errorf("failed to list packages", err)
	}

	for _, pkg := range pkgList {
		arch := pkg.Arch
		if arch == "" {
			arch = "(none)"
		}
		p := types.Package{
			Name:    pkg.Name,
			Epoch:   pkg.Epoch,
			Version: pkg.Version,
			Release: pkg.Release,
			Arch:    arch,
		}
		pkgs = append(pkgs, p)
	}

	return pkgs, nil
}

func (a rpmPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a rpmPkgAnalyzer) Name() string {
	return "rpm"
}
