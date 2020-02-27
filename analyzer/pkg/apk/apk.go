package apk

import (
	"bufio"
	"bytes"
	"log"

	debVersion "github.com/knqyf263/go-deb-version"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterPkgAnalyzer(&alpinePkgAnalyzer{})
}

type alpinePkgAnalyzer struct{}

func (a alpinePkgAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]types.Package, error) {
	pkgMap := map[types.FilePath][]types.Package{}
	detected := false
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		parsedPkgs := a.parseApkInfo(scanner)
		pkgMap[types.FilePath(filename)] = parsedPkgs
		detected = true
	}
	if !detected {
		return nil, analyzer.ErrNoPkgsDetected
	}
	return pkgMap, nil
}

func (a alpinePkgAnalyzer) parseApkInfo(scanner *bufio.Scanner) (pkgs []types.Package) {
	var pkg types.Package
	var version string
	for scanner.Scan() {
		line := scanner.Text()

		// check package if paragraph end
		if len(line) < 2 {
			if analyzer.CheckPackage(&pkg) {
				pkgs = append(pkgs, pkg)
			}
			pkg = types.Package{}
			continue
		}

		switch line[:2] {
		case "P:":
			pkg.Name = line[2:]
		case "V:":
			version = string(line[2:])
			if !debVersion.Valid(version) {
				log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "alpine", pkg.Name, version)
				continue
			}
			pkg.Version = version
		case "o:":
			origin := string(line[2:])
			originPkg := types.Package{
				Name:    origin,
				Version: version,
			}
			if analyzer.CheckPackage(&originPkg) {
				pkgs = append(pkgs, originPkg)
			}
		}
	}
	// in case of last paragraph
	if analyzer.CheckPackage(&pkg) {
		pkgs = append(pkgs, pkg)
	}

	return a.uniquePkgs(pkgs)
}
func (a alpinePkgAnalyzer) uniquePkgs(pkgs []types.Package) (uniqPkgs []types.Package) {
	uniq := map[string]struct{}{}
	for _, pkg := range pkgs {
		if _, ok := uniq[pkg.Name]; ok {
			continue
		}
		uniqPkgs = append(uniqPkgs, pkg)
		uniq[pkg.Name] = struct{}{}
	}
	return uniqPkgs
}

func (a alpinePkgAnalyzer) RequiredFiles() []string {
	return []string{"lib/apk/db/installed"}
}
