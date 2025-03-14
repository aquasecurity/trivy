package rpm

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterAnalyzer(newRPMPkgAnalyzer())
}

const version = 3

var (
	requiredFiles = []string{
		// Berkeley DB
		"usr/lib/sysimage/rpm/Packages",
		"var/lib/rpm/Packages",

		// NDB
		"usr/lib/sysimage/rpm/Packages.db",
		"var/lib/rpm/Packages.db",

		// SQLite3
		"usr/lib/sysimage/rpm/rpmdb.sqlite",
		"var/lib/rpm/rpmdb.sqlite",
	}

	errUnexpectedNameFormat = xerrors.New("unexpected name format")
)

var osVendors = []string{
	"Amazon Linux",          // Amazon Linux 1
	"Amazon.com",            // Amazon Linux 2
	"CentOS",                // CentOS
	"Fedora Project",        // Fedora
	"Oracle America",        // Oracle Linux
	"Red Hat",               // Red Hat
	"AlmaLinux",             // AlmaLinux
	"CloudLinux",            // AlmaLinux
	"VMware",                // Photon OS
	"SUSE",                  // SUSE Linux Enterprise
	"openSUSE",              // openSUSE
	"Microsoft Corporation", // CBL-Mariner
	"Rocky",                 // Rocky Linux
}

type rpmPkgAnalyzer struct{}

func newRPMPkgAnalyzer() *rpmPkgAnalyzer {
	return &rpmPkgAnalyzer{}
}

type RPMDB interface {
	ListPackages() ([]*rpmdb.PackageInfo, error)
}

func (a rpmPkgAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	ctx = log.WithContextPrefix(ctx, "rpm")
	parsedPkgs, installedFiles, err := a.parsePkgInfo(ctx, input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse rpmdb: %w", err)
	}

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

func (a rpmPkgAnalyzer) parsePkgInfo(ctx context.Context, rc io.Reader) (types.Packages, []string, error) {
	filePath, err := writeToTempFile(rc)
	if err != nil {
		return nil, nil, xerrors.Errorf("temp file error: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(filePath)) // Remove the temp dir

	// rpm-python 4.11.3 rpm-4.11.3-35.el7.src.rpm
	// Extract binary package names because RHSA refers to binary package names.
	db, err := rpmdb.Open(filePath)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to open RPM DB: %w", err)
	}
	defer db.Close()

	return a.listPkgs(ctx, db)
}

func (a rpmPkgAnalyzer) listPkgs(ctx context.Context, db RPMDB) (types.Packages, []string, error) {
	// equivalent:
	//   new version: rpm -qa --qf "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{SOURCERPM} %{ARCH}\n"
	//   old version: rpm -qa --qf "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{SOURCERPM} %{ARCH}\n"
	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to list packages: %w", err)
	}

	var pkgs []types.Package
	var installedFiles []string
	provides := make(map[string]string)
	for _, pkg := range pkgList {
		arch := pkg.Arch
		if arch == "" {
			arch = "None"
		}

		// parse source rpm
		var srcName, srcVer, srcRel string
		if pkg.SourceRpm != "(none)" && pkg.SourceRpm != "" {
			// source epoch is not included in SOURCERPM
			srcName, srcVer, srcRel, err = splitFileName(pkg.SourceRpm)
			if err != nil {
				log.DebugContext(ctx, "Invalid Source RPM Found", log.String("sourcerpm", pkg.SourceRpm))
			}
		}

		// Check if the package is vendor-provided.
		// If the package is not provided by vendor, the installed files should not be skipped.
		var files []string
		if packageProvidedByVendor(pkg) {
			files, err = pkg.InstalledFileNames()
			if err != nil {
				return nil, nil, xerrors.Errorf("unable to get installed files: %w", err)
			}

			for i, file := range files {
				files[i] = filepath.ToSlash(file)
			}
		}

		// RPM DB uses MD5 digest
		// https://rpm-software-management.github.io/rpm/manual/tags.html#signatures-and-digests
		var d digest.Digest
		if pkg.SigMD5 != "" {
			d = digest.NewDigestFromString(digest.MD5, pkg.SigMD5)
		}

		var licenses []string
		if pkg.License != "" {
			licenses = []string{pkg.License}
		}

		p := types.Package{
			ID:              fmt.Sprintf("%s@%s-%s.%s", pkg.Name, pkg.Version, pkg.Release, pkg.Arch),
			Name:            pkg.Name,
			Epoch:           pkg.EpochNum(),
			Version:         pkg.Version,
			Release:         pkg.Release,
			Arch:            arch,
			SrcName:         srcName,
			SrcEpoch:        pkg.EpochNum(), // NOTE: use epoch of binary package as epoch of src package
			SrcVersion:      srcVer,
			SrcRelease:      srcRel,
			Modularitylabel: pkg.Modularitylabel,
			Licenses:        licenses,
			DependsOn:       pkg.Requires, // Will be replaced with package IDs
			Maintainer:      pkg.Vendor,
			Digest:          d,
			InstalledFiles:  files,
		}
		pkgs = append(pkgs, p)
		installedFiles = append(installedFiles, files...)

		// It contains mappings between package-providing files and package IDs
		// e.g.
		//	"libc.so.6()(64bit)" => "glibc-2.12-1.212.el6.x86_64"
		//  "rtld(GNU_HASH)"     => "glibc-2.12-1.212.el6.x86_64"
		for _, provide := range pkg.Provides {
			provides[provide] = p.ID
		}
	}

	// Replace required files with package IDs
	consolidateDependencies(pkgs, provides)

	return pkgs, installedFiles, nil
}

func (a rpmPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a rpmPkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRpm
}

func (a rpmPkgAnalyzer) Version() int {
	return version
}

// StaticPaths returns a list of static file paths to analyze
func (a rpmPkgAnalyzer) StaticPaths() []string {
	return requiredFiles
}

// splitFileName returns a name, version, release, epoch, arch:
//
//	e.g.
//		foo-1.0-1.i386.rpm => foo, 1.0, 1, i386
//		1:bar-9-123a.ia64.rpm => bar, 9, 123a, 1, ia64
//
// https://github.com/rpm-software-management/yum/blob/043e869b08126c1b24e392f809c9f6871344c60d/rpmUtils/miscutils.py#L301
func splitFileName(filename string) (name, ver, rel string, err error) {
	filename = strings.TrimSuffix(filename, ".rpm")

	archIndex := strings.LastIndex(filename, ".")
	if archIndex == -1 {
		return "", "", "", errUnexpectedNameFormat
	}

	relIndex := strings.LastIndex(filename[:archIndex], "-")
	if relIndex == -1 {
		return "", "", "", errUnexpectedNameFormat
	}
	rel = filename[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(filename[:relIndex], "-")
	if verIndex == -1 {
		return "", "", "", errUnexpectedNameFormat
	}
	ver = filename[verIndex+1 : relIndex]

	name = filename[:verIndex]
	return name, ver, rel, nil
}

func packageProvidedByVendor(pkg *rpmdb.PackageInfo) bool {
	if pkg.Vendor == "" {
		// Official Amazon packages may not contain `Vendor` field:
		// https://github.com/aquasecurity/trivy/issues/5887
		return strings.Contains(pkg.Release, "amzn")
	}

	for _, vendor := range osVendors {
		if strings.HasPrefix(pkg.Vendor, vendor) {
			return true
		}
	}

	return false
}

func writeToTempFile(rc io.Reader) (string, error) {
	tmpDir, err := os.MkdirTemp("", "rpm")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	filePath := filepath.Join(tmpDir, "Packages")
	f, err := os.Create(filePath)
	if err != nil {
		return "", xerrors.Errorf("failed to create a package file: %w", err)
	}

	if _, err = io.Copy(f, rc); err != nil {
		return "", xerrors.Errorf("failed to copy a package file: %w", err)
	}

	// The temp file must be closed before being opened as Berkeley DB.
	if err = f.Close(); err != nil {
		return "", xerrors.Errorf("failed to close a temp file: %w", err)
	}

	return filePath, nil
}

func consolidateDependencies(pkgs []types.Package, provides map[string]string) {
	for i := range pkgs {
		// e.g. "libc.so.6()(64bit)" => "glibc-2.12-1.212.el6.x86_64"
		pkgs[i].DependsOn = lo.FilterMap(pkgs[i].DependsOn, func(d string, _ int) (string, bool) {
			if pkgID, ok := provides[d]; ok && pkgs[i].ID != pkgID {
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
