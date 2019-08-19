package apk

import (
	"bufio"
	"bytes"
	"log"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"

	debVersion "github.com/knqyf263/go-deb-version"
)

func init() {
	analyzer.RegisterPkgAnalyzer(&alpinePkgAnalyzer{})
}

type alpinePkgAnalyzer struct{}

func (a alpinePkgAnalyzer) Analyze(fileMap extractor.FileMap) (pkgs []analyzer.Package, err error) {
	var parsedPkgs []analyzer.Package
	detected := false
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		parsedPkgs, err = a.parseApkInfo(scanner)
		pkgs = append(pkgs, parsedPkgs...)
		detected = true
	}
	if !detected {
		return pkgs, analyzer.ErrNoPkgsDetected
	}
	return pkgs, nil
}

func (a alpinePkgAnalyzer) parseApkInfo(scanner *bufio.Scanner) (pkgs []analyzer.Package, err error) {
	var pkg analyzer.Package
	var version string
	for scanner.Scan() {
		line := scanner.Text()

		// check package if paragraph end
		if len(line) < 2 {
			if analyzer.CheckPackage(&pkg) {
				pkgs = append(pkgs, pkg)
			}
			pkg = analyzer.Package{}
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
			originPkg := analyzer.Package{
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

	return a.uniquePkgs(pkgs), nil
}
func (a alpinePkgAnalyzer) uniquePkgs(pkgs []analyzer.Package) (uniqPkgs []analyzer.Package) {
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
