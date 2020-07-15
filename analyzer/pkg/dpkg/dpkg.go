package dpkg

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/utils"

	mapset "github.com/deckarep/golang-set"

	"github.com/aquasecurity/fanal/analyzer"

	debVersion "github.com/knqyf263/go-deb-version"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

func init() {
	analyzer.RegisterAnalyzer(&debianPkgAnalyzer{})
}

var (
	requiredFiles = []string{"var/lib/dpkg/status"}
	requiredDirs  = []string{"var/lib/dpkg/status.d/"}
)

type debianPkgAnalyzer struct{}

func (a debianPkgAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	parsedPkgs := a.parseDpkginfo(scanner)
	return analyzer.AnalyzeReturn{
		Packages: parsedPkgs,
	}, nil
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
		isInstalled   bool
		sourceVersion string
	)
	isInstalled = true
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
		} else if strings.HasPrefix(line, "Status: ") {
			for _, ss := range strings.Fields(strings.TrimPrefix(line, "Status: ")) {
				if ss == "deinstall" || ss == "purge" {
					isInstalled = false
					break
				}
			}
		}
		if !scanner.Scan() {
			break
		}
	}

	if name == "" || version == "" || !isInstalled {
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

func (a debianPkgAnalyzer) Required(filePath string, fileInfo os.FileInfo) bool {
	if utils.StringInSlice(filePath, requiredFiles) {
		return true
	}

	dir := filepath.Dir(filePath) + "/"
	if utils.StringInSlice(dir, requiredDirs) {
		return true
	}
	return false
}

func (a debianPkgAnalyzer) Name() string {
	return "dpkg"
}
