package apk

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	apkVersion "github.com/knqyf263/go-apk-version"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterAnalyzer(&alpinePkgAnalyzer{})
}

const analyzerVersion = 2

var requiredFiles = []string{"lib/apk/db/installed"}

type alpinePkgAnalyzer struct{}

func (a alpinePkgAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	parsedPkgs, installedFiles := a.parseApkInfo(scanner)

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: parsedPkgs,
			},
		},
		SystemInstalledFiles: installedFiles,
	}, nil
}

func (a alpinePkgAnalyzer) parseApkInfo(scanner *bufio.Scanner) ([]types.Package, map[string][]string) {
	var (
		pkgs           []types.Package
		pkg            types.Package
		version        string
		dir            string
		installedFiles = make(map[string][]string)
		provides       = map[string]string{} // for dependency graph
	)

	for scanner.Scan() {
		line := scanner.Text()

		// check package if paragraph end
		if len(line) < 2 {
			if !pkg.Empty() {
				pkgs = append(pkgs, pkg)
			}
			pkg = types.Package{}
			continue
		}

		// ref. https://wiki.alpinelinux.org/wiki/Apk_spec
		switch line[:2] {
		case "P:":
			pkg.Name = line[2:]
		case "V:":
			version = line[2:]
			if !apkVersion.Valid(version) {
				log.Logger.Warnf("Invalid Version Found : OS %s, Package %s, Version %s", "alpine", pkg.Name, version)
				continue
			}
			pkg.Version = version
		case "o:":
			origin := line[2:]
			pkg.SrcName = origin
			pkg.SrcVersion = version
		case "L:":
			pkg.Licenses = a.parseLicense(line)
		case "F:":
			dir = line[2:]
		case "R:":
			pkg.SystemInstalledFiles = append(pkg.SystemInstalledFiles, filepath.Join(dir, line[2:]))
		case "p:": // provides (corresponds to provides in PKGINFO, concatenated by spaces into a single line)
			a.parseProvides(line, pkg.ID, provides)
		case "D:": // dependencies (corresponds to depend in PKGINFO, concatenated by spaces into a single line)
			pkg.DependsOn = a.parseDependencies(line)
		}

		if pkg.Name != "" && pkg.Version != "" {
			pkg.ID = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)

			// Dependencies could be package names or provides, so package names are stored as provides here.
			// e.g. D:scanelf so:libc.musl-x86_64.so.1
			provides[pkg.Name] = pkg.ID
		}
	}
	// in case of last paragraph
	if !pkg.Empty() {
		pkgs = append(pkgs, pkg)
	}
	if pkg.Name != "" {
		installedFiles[pkg.Name] = pkg.SystemInstalledFiles
	}

	pkgs = a.uniquePkgs(pkgs)

	// Replace dependencies with package IDs
	a.consolidateDependencies(pkgs, provides)

	return pkgs, installedFiles
}

func (a alpinePkgAnalyzer) trimRequirement(s string) string {
	// Trim version requirements
	// e.g.
	//   so:libssl.so.1.1=1.1 => so:libssl.so.1.1
	//   musl>=1.2 => musl
	if strings.ContainsAny(s, "<>=") {
		s = s[:strings.IndexAny(s, "><=")]
	}
	return s
}

func (a alpinePkgAnalyzer) parseLicense(line string) []string {
	line = line[2:] // Remove "L:"
	if line == "" {
		return nil
	}
	var licenses []string
	// e.g. MPL 2.0 GPL2+ => {"MPL2.0", "GPL2+"}
	for i, s := range strings.Fields(line) {
		s = strings.Trim(s, "()")
		if s == "AND" || s == "OR" {
			continue
		} else if i > 0 && (s == "1.0" || s == "2.0" || s == "3.0") {
			licenses[i-1] = licensing.Normalize(licenses[i-1] + s)
		} else {
			licenses = append(licenses, licensing.Normalize(s))
		}
	}
	return licenses
}

func (a alpinePkgAnalyzer) parseProvides(line, pkgID string, provides map[string]string) {
	for _, p := range strings.Fields(line[2:]) {
		p = a.trimRequirement(p)

		// Assume name ("P:") and version ("V:") are defined before provides ("p:")
		provides[p] = pkgID
	}
}

func (a alpinePkgAnalyzer) parseDependencies(line string) []string {
	line = line[2:] // Remove "D:"
	return lo.FilterMap(strings.Fields(line), func(d string, _ int) (string, bool) {
		// e.g. D:!uclibc-utils scanelf musl=1.1.14-r10 so:libc.musl-x86_64.so.1
		if strings.HasPrefix(d, "!") {
			return "", false
		}
		return a.trimRequirement(d), true
	})
}

func (a alpinePkgAnalyzer) consolidateDependencies(pkgs []types.Package, provides map[string]string) {
	for i := range pkgs {
		// e.g. libc6 => libc6@2.31-13+deb11u4
		pkgs[i].DependsOn = lo.FilterMap(pkgs[i].DependsOn, func(d string, _ int) (string, bool) {
			if pkgID, ok := provides[d]; ok {
				return pkgID, true
			}
			return "", false
		})
		sort.Strings(pkgs[i].DependsOn)
		pkgs[i].DependsOn = slices.Compact(pkgs[i].DependsOn)

		if len(pkgs[i].DependsOn) == 0 {
			pkgs[i].DependsOn = nil
		}
	}
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

func (a alpinePkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a alpinePkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApk
}

func (a alpinePkgAnalyzer) Version() int {
	return analyzerVersion
}
