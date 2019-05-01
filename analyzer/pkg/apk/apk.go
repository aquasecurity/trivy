package apk

import (
	"bufio"
	"bytes"
	"log"

	"github.com/pkg/errors"

	"github.com/coreos/clair/ext/versionfmt"
	clairDpkg "github.com/coreos/clair/ext/versionfmt/dpkg"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
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
		return pkgs, errors.New("No package detected")
	}
	return pkgs, nil
}

func (a alpinePkgAnalyzer) parseApkInfo(scanner *bufio.Scanner) (pkgs []analyzer.Package, err error) {
	var pkg analyzer.Package
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
			version := string(line[2:])
			err = versionfmt.Valid(clairDpkg.ParserName, version)
			if err != nil {
				log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "alpine", pkg.Name, version)
				continue
			} else {
				pkg.Version = version
			}
		}
	}
	// in case of last paragraph
	if analyzer.CheckPackage(&pkg) {
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func (a alpinePkgAnalyzer) RequiredFiles() []string {
	return []string{"lib/apk/db/installed"}
}
