package dpkg

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"regexp"
	"strings"

	"github.com/deckarep/golang-set"

	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	clairDpkg "github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
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
		return pkgs, errors.New("No package detected")
	}
	return pkgs, nil
}

func (a debianPkgAnalyzer) parseDpkginfo(scanner *bufio.Scanner) (pkgs []analyzer.Package) {
	var bin, src *analyzer.Package
	pkgMap := mapset.NewSet()
	srcPkgMap := mapset.NewSet()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			bin = nil
			src = nil
			continue
		}

		bin, src = a.parseDpkgPkg(scanner)
		if bin != nil {
			pkgMap.Add(*bin)
		}

		if src != nil {
			srcPkgMap.Add(*src)
		}
	}
	pkgs = mapsetToSlice(pkgMap)
	pkgs = append(pkgs, mapsetToSlice(srcPkgMap)...)
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

func (a debianPkgAnalyzer) parseDpkgPkg(scanner *bufio.Scanner) (binPkg *analyzer.Package, srcPkg *analyzer.Package) {
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

	if name != "" && version != "" {
		if err := versionfmt.Valid(clairDpkg.ParserName, version); err != nil {
			log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "debian", name, version)
		} else {
			binPkg = &analyzer.Package{Name: name, Version: version, Type: analyzer.TypeBinary}
		}
	}

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

	if sourceName != "" && sourceVersion != "" {
		if err := versionfmt.Valid(dpkg.ParserName, version); err != nil {
			log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "debian", name, version)
		} else {
			srcPkg = &analyzer.Package{Name: sourceName, Version: sourceVersion, Type: analyzer.TypeSource}
		}
	}
	return binPkg, srcPkg
}

func (a debianPkgAnalyzer) RequiredFiles() []string {
	return []string{"var/lib/dpkg/status"}
}
