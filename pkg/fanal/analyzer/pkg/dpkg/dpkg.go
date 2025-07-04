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
	"slices"
	"sort"
	"strings"

	debVersion "github.com/knqyf263/go-deb-version"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeDpkg, newDpkgAnalyzer)
}

type dpkgAnalyzer struct {
	logger *log.Logger
}

func newDpkgAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &dpkgAnalyzer{
		logger: log.WithPrefix("dpkg"),
	}, nil
}

const (
	analyzerVersion = 5

	statusFile    = "var/lib/dpkg/status"
	statusDir     = "var/lib/dpkg/status.d/"
	infoDir       = "var/lib/dpkg/info/"
	availableFile = "var/lib/dpkg/available"

	md5sumsExtension = ".md5sums"
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
		a.logger.Debug("Unable to parse the available file", log.FilePath(availableFile), log.Err(err))
	}

	required := func(path string, _ fs.DirEntry) bool {
		return path != availableFile
	}

	packageFiles := make(map[string][]string)

	// parse other files
	err = fsutils.WalkDir(input.FS, ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		// parse *md5sums files
		if a.isMd5SumsFile(filepath.Split(path)) {
			scanner := bufio.NewScanner(r)
			systemFiles, err := a.parseDpkgMd5sums(scanner)
			if err != nil {
				return xerrors.Errorf("failed to parse %s file: %w", path, err)
			}
			packageFiles[strings.TrimSuffix(filepath.Base(path), md5sumsExtension)] = systemFiles
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

	// map the packages to their respective files
	for i, pkgInfo := range packageInfos {
		for j, pkg := range pkgInfo.Packages {
			installedFiles, found := packageFiles[pkg.Name]
			if !found {
				installedFiles = packageFiles[pkg.Name+":"+pkg.Arch]
			}
			packageInfos[i].Packages[j].InstalledFiles = installedFiles
		}
	}

	return &analyzer.AnalysisResult{
		PackageInfos:         packageInfos,
		SystemInstalledFiles: systemInstalledFiles,
	}, nil

}

// parseDpkgMd5sums parses `/var/lib/dpkg/*/*.md5sums` file.
//
// `*.md5sums` files don't contain links (see https://github.com/aquasecurity/trivy/pull/9131#discussion_r2182557288).
// But Trivy doesn't support links, so this will not cause problems.
// TODO use `*.list` files instead of `*.md5sums` files when Trivy will support links.
func (a dpkgAnalyzer) parseDpkgMd5sums(scanner *bufio.Scanner) ([]string, error) {
	var installedFiles []string
	for scanner.Scan() {
		current := scanner.Text()

		// md5sums file use the following format:
		// <digest>  <filepath> (2 spaces)
		// cf. https://man7.org/linux/man-pages/man5/deb-md5sums.5.html
		_, file, ok := strings.Cut(current, "  ")
		if !ok {
			return nil, xerrors.Errorf("invalid md5sums line format: %s", current)
		}
		installedFiles = append(installedFiles, "/"+file) // md5sums files don't contain leading slash
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	sort.Strings(installedFiles)
	return installedFiles, nil
}

// parseDpkgAvailable parses /var/lib/dpkg/available
func (a dpkgAnalyzer) parseDpkgAvailable(fsys fs.FS) (map[string]digest.Digest, error) {
	f, err := fsys.Open(availableFile)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	pkgs := make(map[string]digest.Digest)
	scanner := NewScanner(f)
	for scanner.Scan() {
		header, err := scanner.Header()
		if !errors.Is(err, io.EOF) && err != nil {
			a.logger.Warn("Parse error", log.FilePath(availableFile), log.Err(err))
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
func (a dpkgAnalyzer) parseDpkgStatus(filePath string, r io.Reader, digests map[string]digest.Digest) ([]types.PackageInfo, error) {
	var pkg *types.Package
	pkgs := make(map[string]*types.Package)
	pkgIDs := make(map[string]string)

	scanner := NewScanner(r)
	for scanner.Scan() {
		header, err := scanner.Header()
		if !errors.Is(err, io.EOF) && err != nil {
			a.logger.Warn("Parse error", log.FilePath(filePath), log.Err(err))
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
		md := make(map[string]string)
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
		a.logger.Warn("Invalid version", log.String("OS", "debian"),
			log.String("package", pkg.Name), log.String("version", pkg.Version))
		return nil
	} else {
		pkg.ID = a.pkgID(pkg.Name, pkg.Version)
		pkg.Version = v.Version()
		pkg.Epoch = v.Epoch()
		pkg.Release = v.Revision()
	}

	if v, err := debVersion.NewVersion(pkg.SrcVersion); err != nil {
		a.logger.Warn("Invalid source version", log.String("OS", "debian"),
			log.String("package", pkg.Name), log.String("version", pkg.SrcVersion))
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
	if a.isMd5SumsFile(dir, fileName) || filePath == statusFile || filePath == availableFile || dir == statusDir {
		return true
	}

	return false
}

func (a dpkgAnalyzer) pkgID(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}

func (a dpkgAnalyzer) parseStatus(s string) bool {
	for ss := range strings.FieldsSeq(s) {
		if ss == "deinstall" || ss == "purge" {
			return false
		}
	}
	return true
}

func (a dpkgAnalyzer) parseDepends(s string) []string {
	// e.g. passwd, debconf (>= 0.5) | debconf-2.0
	var dependencies []string
	for dep := range strings.SplitSeq(s, ",") {
		// e.g. gpgv | gpgv2 | gpgv1
		for d := range strings.SplitSeq(dep, "|") {
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
	s, _, _ = strings.Cut(s, "(")
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

func (a dpkgAnalyzer) isMd5SumsFile(dir, fileName string) bool {
	// - var/lib/dpkg/info/*.md5sums is default path
	// - var/lib/dpkg/status.d/*.md5sums path in distroless images (see https://github.com/GoogleContainerTools/distroless/blob/5c119701429fb742ab45682cfc3073f911bad4bf/PACKAGE_METADATA.md#omitted-files)
	if dir != infoDir && dir != statusDir {
		return false
	}

	return strings.HasSuffix(fileName, md5sumsExtension)
}

func (a dpkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDpkg
}

func (a dpkgAnalyzer) Version() int {
	return analyzerVersion
}

// StaticPaths returns a list of static file paths to analyze
func (a dpkgAnalyzer) StaticPaths() []string {
	return []string{
		statusFile,
		availableFile,
		statusDir,
		infoDir,
	}
}
