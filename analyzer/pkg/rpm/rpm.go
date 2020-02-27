package rpm

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

func init() {
	analyzer.RegisterPkgAnalyzer(&rpmPkgAnalyzer{})
}

type rpmPkgAnalyzer struct{}

func (a rpmPkgAnalyzer) Analyze(fileMap extractor.FileMap) (pkgs map[types.FilePath][]types.Package, err error) {
	pkgMap := map[types.FilePath][]types.Package{}
	detected := false
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		parsedPkgs, err := a.parsePkgInfo(file)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse the pkg info: %w", err)
		}
		pkgMap[types.FilePath(filename)] = parsedPkgs
		detected = true
	}
	if !detected {
		return nil, analyzer.ErrNoPkgsDetected
	}
	return pkgMap, nil
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
	db := rpmdb.DB{}
	if err = db.Open(filename); err != nil {
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

func (a rpmPkgAnalyzer) RequiredFiles() []string {
	return []string{
		"usr/lib/sysimage/rpm/Packages",
		"var/lib/rpm/Packages",
	}
}
