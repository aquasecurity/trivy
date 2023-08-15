package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	debVersion "github.com/knqyf263/go-deb-version"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeDpkg, newDpkgAnalyzer)
}

type dpkgAnalyzer struct{}

func newDpkgAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &dpkgAnalyzer{}, nil
}

const (
	analyzerVersion = 5

	statusFile    = "var/lib/dpkg/status"
	statusDir     = "var/lib/dpkg/status.d/"
	infoDir       = "var/lib/dpkg/info/"
	availableFile = "var/lib/dpkg/available"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`(?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

func (a dpkgAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var systemInstalledFiles []string
	var packageInfos []types.PackageInfo

	// parse `available` file to get digest for packages
	digests, err := a.parseDpkgAvailable(input.FS)
	if err != nil {
		log.Logger.Debugf("Unable to parse %q file: %s", availableFile, err)
	}

	required := func(path string, d fs.DirEntry) bool {
		return path != availableFile
	}

	// parse other files
	err = fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		// parse list files
		if a.isListFile(filepath.Split(path)) {
			scanner := bufio.NewScanner(r)
			systemFiles, err := a.parseDpkgInfoList(scanner)
			if err != nil {
				return err
			}
			systemInstalledFiles = append(systemInstalledFiles, systemFiles...)
			return nil
		}
		// parse status files
		infos, err := a.parseDpkgStatus(path, r, digests)
		if err != nil {
			return err
		}
		packageInfos = append(packageInfos, infos...)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("dpkg walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		PackageInfos:         packageInfos,
		SystemInstalledFiles: systemInstalledFiles,
	}, nil

}

// parseDpkgInfoList parses /var/lib/dpkg/info/*.list
func (a dpkgAnalyzer) parseDpkgInfoList(scanner *bufio.Scanner) ([]string, error) {
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

	return installedFiles, nil
}

// parseDpkgAvailable parses /var/lib/dpkg/available
func (a dpkgAnalyzer) parseDpkgAvailable(fsys fs.FS) (map[string]digest.Digest, error) {
	f, err := fsys.Open(availableFile)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	pkgs := map[string]digest.Digest{}
	scanner := NewScanner(f)
	for scanner.Scan() {
		header, err := scanner.Header()
		if !errors.Is(err, io.EOF) && err != nil {
			log.Logger.Warnw("Parse error", zap.String("file", availableFile), zap.Error(err))
			continue
		}
		name, version, checksum := header.Get("Package"), header.Get("Version"), header.Get("SHA256")
		pkgID := a.pkgID(name, version)
		if pkgID != "" && checksum != "" {
			pkgs[pkgID] = digest.NewDigestFromString(digest.SHA256, checksum)
		}
	}
	if err = scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	return pkgs, nil
}

// parseDpkgStatus parses /var/lib/dpkg/status or /var/lib/dpkg/status/*
func (a dpkgAnalyzer) parseDpkgStatus(filePath string, r dio.ReadSeekerAt, digests map[string]digest.Digest) ([]types.PackageInfo, error) {
	var pkg *types.Package
	pkgs := map[string]*types.Package{}
	pkgIDs := map[string]string{}

	scanner := NewScanner(r)
	for scanner.Scan() {
		header, err := scanner.Header()
		if !errors.Is(err, io.EOF) && err != nil {
			log.Logger.Warnw("Parse error", zap.String("file", filePath), zap.Error(err))
			continue
		}

		pkg = a.parseDpkgPkg(header)
		if pkg != nil {
			pkg.Digest = digests[pkg.ID]
			pkgs[pkg.ID] = pkg
			pkgIDs[pkg.Name] = pkg.ID
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	a.consolidateDependencies(pkgs, pkgIDs)

	return []types.PackageInfo{
		{
			FilePath: filePath,
			Packages: lo.MapToSlice(pkgs, func(_ string, p *types.Package) types.Package {
				return *p
			}),
		},
	}, nil
}

func (a dpkgAnalyzer) parseDpkgPkg(header textproto.MIMEHeader) *types.Package {
	if isInstalled := a.parseStatus(header.Get("Status")); !isInstalled {
		return nil
	}

	pkg := &types.Package{
		Name:       header.Get("Package"),
		Version:    header.Get("Version"),                 // Will be parsed later
		DependsOn:  a.parseDepends(header.Get("Depends")), // Will be updated later
		Maintainer: header.Get("Maintainer"),
		Arch:       header.Get("Architecture"),
	}
	if pkg.Name == "" || pkg.Version == "" {
		return nil
	}

	// Source line (Optional)
	// Gives the name of the source package
	// May also specifies a version
	if src := header.Get("Source"); src != "" {
		srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(src, -1)[0]
		md := map[string]string{}
		for i, n := range srcCapture {
			md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
		}
		pkg.SrcName = md["name"]
		pkg.SrcVersion = md["version"]
	}

	// Source version and names are computed from binary package names and versions in dpkg.
	// Source package name:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n338
	// Source package version:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n355
	if pkg.SrcName == "" {
		pkg.SrcName = pkg.Name
	}
	if pkg.SrcVersion == "" {
		pkg.SrcVersion = pkg.Version
	}

	if v, err := debVersion.NewVersion(pkg.Version); err != nil {
		log.Logger.Warnw("Invalid version", zap.String("OS", "debian"),
			zap.String("package", pkg.Name), zap.String("version", pkg.Version))
		return nil
	} else {
		pkg.ID = a.pkgID(pkg.Name, pkg.Version)
		pkg.Version = v.Version()
		pkg.Epoch = v.Epoch()
		pkg.Release = v.Revision()
	}

	if v, err := debVersion.NewVersion(pkg.SrcVersion); err != nil {
		log.Logger.Warnw("Invalid source version", zap.String("OS", "debian"),
			zap.String("package", pkg.Name), zap.String("version", pkg.SrcVersion))
		return nil
	} else {
		pkg.SrcVersion = v.Version()
		pkg.SrcEpoch = v.Epoch()
		pkg.SrcRelease = v.Revision()
	}

	return pkg
}

func (a dpkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, fileName := filepath.Split(filePath)
	if a.isListFile(dir, fileName) || filePath == statusFile || filePath == availableFile {
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

func (a dpkgAnalyzer) parseStatus(s string) bool {
	for _, ss := range strings.Fields(s) {
		if ss == "deinstall" || ss == "purge" {
			return false
		}
	}
	return true
}

func (a dpkgAnalyzer) parseDepends(s string) []string {
	// e.g. passwd, debconf (>= 0.5) | debconf-2.0
	var dependencies []string
	depends := strings.Split(s, ",")
	for _, dep := range depends {
		// e.g. gpgv | gpgv2 | gpgv1
		for _, d := range strings.Split(dep, "|") {
			d = a.trimVersionRequirement(d)

			// Store only uniq package names here
			d = strings.TrimSpace(d)
			if !slices.Contains(dependencies, d) {
				dependencies = append(dependencies, d)
			}
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
