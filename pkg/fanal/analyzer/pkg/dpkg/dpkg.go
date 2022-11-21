package dpkg

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	debVersion "github.com/knqyf263/go-deb-version"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterAnalyzer(&dpkgAnalyzer{})
}

const (
	analyzerVersion = 3

	statusFile = "var/lib/dpkg/status"
	statusDir  = "var/lib/dpkg/status.d/"
	infoDir    = "var/lib/dpkg/info/"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

type dpkgAnalyzer struct{}

func (a dpkgAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	if a.isListFile(filepath.Split(input.FilePath)) {
		return a.parseDpkgInfoList(input.FilePath, scanner)
	}

	return a.parseDpkgStatus(input.FilePath, scanner)
}

// parseDpkgStatus parses /var/lib/dpkg/info/*.list
func (a dpkgAnalyzer) parseDpkgInfoList(filePath string, scanner *bufio.Scanner) (*analyzer.AnalysisResult, error) {
	var installedFiles []string
	var previous string

	for scanner.Scan() {
		current := scanner.Text()
		if current == "/." {
			continue
		}

		// Add the file if it is not directory.
		// e.g.
		//  /usr/sbin
		//  /usr/sbin/tarcat
		//
		// In the above case, we should take only /usr/sbin/tarcat since /usr/sbin is a directory
		if !strings.HasPrefix(current, previous+"/") {
			installedFiles = append(installedFiles, previous)
		}
		previous = current
	}

	// Add the last file
	installedFiles = append(installedFiles, previous)

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	return &analyzer.AnalysisResult{
		SystemInstalledFiles: map[string][]string{strings.TrimSuffix(filepath.Base(filePath), ".list"): installedFiles},
	}, nil
}

// parseDpkgStatus parses /var/lib/dpkg/status or /var/lib/dpkg/status/*
func (a dpkgAnalyzer) parseDpkgStatus(filePath string, scanner *bufio.Scanner) (*analyzer.AnalysisResult, error) {
	var pkg *types.Package
	pkgs := map[string]*types.Package{}
	pkgIDs := map[string]string{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		pkg = a.parseDpkgPkg(scanner)
		if pkg != nil {
			pkgs[pkg.ID] = pkg
			pkgIDs[pkg.Name] = pkg.ID
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	a.consolidateDependencies(pkgs, pkgIDs)

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: filePath,
				Packages: lo.MapToSlice(pkgs, func(_ string, p *types.Package) types.Package {
					return *p
				}),
			},
		},
	}, nil
}

func (a dpkgAnalyzer) parseDpkgPkg(scanner *bufio.Scanner) (pkg *types.Package) {
	var (
		name          string
		version       string
		sourceName    string
		dependencies  []string
		isInstalled   bool
		sourceVersion string
		maintainer    string
		architecture  string
	)
	isInstalled = true
	for {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		switch {
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Source: "):
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
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Status: "):
			isInstalled = a.parseStatus(line)
		case strings.HasPrefix(line, "Depends: "):
			dependencies = a.parseDepends(line)
		case strings.HasPrefix(line, "Maintainer: "):
			maintainer = strings.TrimSpace(strings.TrimPrefix(line, "Maintainer: "))
		case strings.HasPrefix(line, "Architecture: "):
			architecture = strings.TrimPrefix(line, "Architecture: ")
		}
		if !scanner.Scan() {
			break
		}
	}

	if name == "" || version == "" || !isInstalled {
		return nil
	} else if !debVersion.Valid(version) {
		log.Logger.Warnf("Invalid Version Found : OS %s, Package %s, Version %s", "debian", name, version)
		return nil
	}
	pkg = &types.Package{
		ID:         a.pkgID(name, version),
		Name:       name,
		Version:    version,
		DependsOn:  dependencies, // Will be consolidated later
		Maintainer: maintainer,
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

	if !debVersion.Valid(sourceVersion) {
		log.Logger.Warnf("Invalid Version Found : OS %s, Package %s, Version %s", "debian", sourceName, sourceVersion)
		return pkg
	}
	pkg.SrcName = sourceName
	pkg.SrcVersion = sourceVersion
	pkg.Arch = architecture

	return pkg
}

func (a dpkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, fileName := filepath.Split(filePath)
	if a.isListFile(dir, fileName) || filePath == statusFile {
		return true
	}

	if dir == statusDir {
		return true
	}
	return false
}

func (a dpkgAnalyzer) pkgID(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}

func (a dpkgAnalyzer) parseStatus(line string) bool {
	for _, ss := range strings.Fields(strings.TrimPrefix(line, "Status: ")) {
		if ss == "deinstall" || ss == "purge" {
			return false
		}
	}
	return true
}

func (a dpkgAnalyzer) parseDepends(line string) []string {
	line = strings.TrimPrefix(line, "Depends: ")
	// e.g. Depends: passwd, debconf (>= 0.5) | debconf-2.0

	var dependencies []string
	depends := strings.Split(line, ",")
	for _, dep := range depends {
		// e.g. gpgv | gpgv2 | gpgv1
		for _, d := range strings.Split(dep, "|") {
			d = a.trimVersionRequirement(d)

			// Store only package names here
			dependencies = append(dependencies, strings.TrimSpace(d))
		}
	}
	return dependencies
}

func (a dpkgAnalyzer) trimVersionRequirement(s string) string {
	// e.g.
	//	libapt-pkg6.0 (>= 2.2.4) => libapt-pkg6.0
	//	adduser => adduser
	if strings.Contains(s, "(") {
		s = s[:strings.Index(s, "(")]
	}
	return s
}

func (a dpkgAnalyzer) consolidateDependencies(pkgs map[string]*types.Package, pkgIDs map[string]string) {
	for _, pkg := range pkgs {
		// e.g. libc6 => libc6@2.31-13+deb11u4
		pkg.DependsOn = lo.FilterMap(pkg.DependsOn, func(d string, _ int) (string, bool) {
			if pkgID, ok := pkgIDs[d]; ok {
				return pkgID, true
			}
			return "", false
		})
		sort.Strings(pkg.DependsOn)
		if len(pkg.DependsOn) == 0 {
			pkg.DependsOn = nil
		}
	}
}

func (a dpkgAnalyzer) isListFile(dir, fileName string) bool {
	if dir != infoDir {
		return false
	}

	return strings.HasSuffix(fileName, ".list")
}

func (a dpkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDpkg
}

func (a dpkgAnalyzer) Version() int {
	return analyzerVersion
}
