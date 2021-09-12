package dpkg

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	debVersion "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&dpkgAnalyzer{})
}

const (
	version = 2

	statusFile = "var/lib/dpkg/status"
	statusDir  = "var/lib/dpkg/status.d/"
	infoDir    = "var/lib/dpkg/info/"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

type dpkgAnalyzer struct{}

func (a dpkgAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	if a.isListFile(filepath.Split(target.FilePath)) {
		return a.parseDpkgInfoList(scanner)
	}

	return a.parseDpkgStatus(target.FilePath, scanner)
}

// parseDpkgStatus parses /var/lib/dpkg/info/*.list
func (a dpkgAnalyzer) parseDpkgInfoList(scanner *bufio.Scanner) (*analyzer.AnalysisResult, error) {
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
		SystemInstalledFiles: installedFiles,
	}, nil
}

// parseDpkgStatus parses /var/lib/dpkg/status or /var/lib/dpkg/status/*
func (a dpkgAnalyzer) parseDpkgStatus(filePath string, scanner *bufio.Scanner) (*analyzer.AnalysisResult, error) {
	var pkg *types.Package
	pkgMap := map[string]*types.Package{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			pkg = nil
			continue
		}

		pkg = a.parseDpkgPkg(scanner)
		if pkg != nil {
			pkgMap[pkg.Name+"-"+pkg.Version] = pkg
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	pkgs := make([]types.Package, 0, len(pkgMap))
	for _, p := range pkgMap {
		pkgs = append(pkgs, *p)
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: filePath,
				Packages: pkgs,
			},
		},
	}, nil
}

func (a dpkgAnalyzer) parseDpkgPkg(scanner *bufio.Scanner) (pkg *types.Package) {
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
	return version
}
