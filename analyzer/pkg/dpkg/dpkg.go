package dpkg

import (
	"bufio"
	"bytes"
	"log"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/utils"

	mapset "github.com/deckarep/golang-set"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"

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

func (a debianPkgAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]types.Package, error) {
	pkgMap := map[types.FilePath][]types.Package{}
	detected := false
	for filename, targetBytes := range fileMap {
		dir := filepath.Dir(filename) + "/"
		if !utils.StringInSlice(filename, a.requiredFiles()) && !utils.StringInSlice(dir, a.requiredDirs()) {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(targetBytes))
		parsedPkgs := a.parseDpkginfo(scanner)
		pkgMap[types.FilePath(filename)] = parsedPkgs
		detected = true
	}
	if !detected {
		return nil, analyzer.ErrNoPkgsDetected
	}
	return pkgMap, nil
}

func (a debianPkgAnalyzer) parseDpkginfo(scanner *bufio.Scanner) (pkgs []types.Package) {
	var pkg *types.Package
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

func mapsetToSlice(features mapset.Set) []types.Package {
	uniqueLayerFeatures := make([]types.Package, 0, features.Cardinality())
	for f := range features.Iter() {
		feature := f.(types.Package)
		uniqueLayerFeatures = append(uniqueLayerFeatures, feature)
	}
	return uniqueLayerFeatures
}

func (a debianPkgAnalyzer) parseDpkgPkg(scanner *bufio.Scanner) (pkg *types.Package) {
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
	pkg = &types.Package{Name: name, Version: version}

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
	return append(a.requiredFiles(), a.requiredDirs()...)
}

func (a debianPkgAnalyzer) requiredFiles() []string {
	return []string{"var/lib/dpkg/status"}
}

func (a debianPkgAnalyzer) requiredDirs() []string {
	return []string{"var/lib/dpkg/status.d/"}
}
