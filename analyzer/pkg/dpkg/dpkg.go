package dpkg

import (
	"bufio"
	"bytes"
	"log"
	"regexp"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"

	debVersion "github.com/knqyf263/go-deb-version"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

func init() {
	analyzer.RegisterPkgAnalyzer(&debianPkgAnalyzer{})
}

type debianPkgAnalyzer struct{}

func (a debianPkgAnalyzer) Analyze(fileMap extractor.FileMap) (pkgs []analyzer.Package, err error) {
	detected := false
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		pkgs = a.parseDpkginfo(scanner)
		detected = true
	}
	if !detected {
		return pkgs, xerrors.New("no package detected")
	}
	return pkgs, nil
}

func (a debianPkgAnalyzer) parseDpkginfo(scanner *bufio.Scanner) (pkgs []analyzer.Package) {
	var pkg *analyzer.Package
	pkgMap := mapset.NewSet()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			pkg = nil
			continue
		}

		pkg = a.parseDpkgPkg(scanner)
		if pkg != nil {
			pkgMap.Add(*pkg)
		}
	}
	pkgs = mapsetToSlice(pkgMap)
	return pkgs
}

func mapsetToSlice(features mapset.Set) []analyzer.Package {
	uniqueLayerFeatures := make([]analyzer.Package, 0, features.Cardinality())
	for f := range features.Iter() {
		feature := f.(analyzer.Package)
		uniqueLayerFeatures = append(uniqueLayerFeatures, feature)
	}
	return uniqueLayerFeatures
}

func (a debianPkgAnalyzer) parseDpkgPkg(scanner *bufio.Scanner) (pkg *analyzer.Package) {
	var (
		name          string
		version       string
		sourceName    string
		sourceVersion string
	)

	for {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Package: ") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optional)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			sourceName = md["name"]
			if md["version"] != "" {
				sourceVersion = md["version"]
			}
		} else if strings.HasPrefix(line, "Version: ") {
			version = strings.TrimPrefix(line, "Version: ")
		}

		if !scanner.Scan() {
			break
		}
	}

	if name == "" || version == "" {
		return nil
	} else if !debVersion.Valid(version) {
		log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "debian", name, version)
		return nil
	}
	pkg = &analyzer.Package{Name: name, Version: version}

	// Source version and names are computed from binary package names and versions
	// in dpkg.
	// Source package name:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n338
	// Source package version:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n355
	if sourceName == "" {
		sourceName = name
	}

	if sourceVersion == "" {
		sourceVersion = version
	}

	if !debVersion.Valid(sourceVersion) {
		log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "debian", sourceName, sourceVersion)
		return pkg
	}
	pkg.SrcName = sourceName
	pkg.SrcVersion = sourceVersion

	return pkg
}

func (a debianPkgAnalyzer) RequiredFiles() []string {
	return []string{"var/lib/dpkg/status"}
}
