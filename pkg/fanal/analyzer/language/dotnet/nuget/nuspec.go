package nuget

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const nuspecExt = "nuspec"

var _ types.PackageManifestParser = (*nuspecParser)(nil)

// https://learn.microsoft.com/en-us/nuget/reference/nuspec
type Package struct {
	ID       string
	Metadata Metadata `xml:"metadata"`
}

type Metadata struct {
	Name    string  `xml:"id"`
	Version string  `xml:"version"`
	License License `xml:"license"`
}

type License struct {
	Text string `xml:",chardata"`
	Type string `xml:"type,attr"`
}

type nuspecParser struct {
	logger        *log.Logger
	licenseConfig types.LicenseScanConfig
	packagesDir   string // global packages folder - https: //learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
}

func newNuspecParser(logger *log.Logger) nuspecParser {
	// cf. https: //learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
	packagesDir := os.Getenv("NUGET_PACKAGES")
	if packagesDir == "" {
		packagesDir = filepath.Join(os.Getenv("HOME"), ".nuget", "packages")
	}

	if !fsutils.DirExists(packagesDir) {
		return nuspecParser{}
	}

	return nuspecParser{
		logger:      logger,
		packagesDir: packagesDir,
	}
}

func (p nuspecParser) findLicense(name, version string) ([]types.License, error) {
	if p.packagesDir == "" {
		return nil, nil
	}

	// If deep license scanning is enabled, we scan every file present within the given nuget package
	// and search for concluded licenses
	if p.licenseConfig.EnableDeepLicenseScan {
		return p.findConcludedLicenses(name, version)
	}

	// package path uses lowercase letters only
	// e.g. `$HOME/.nuget/packages/newtonsoft.json/13.0.3/newtonsoft.json.nuspec`
	// for `Newtonsoft.Json` v13.0.3
	name = strings.ToLower(name)
	version = strings.ToLower(version)

	nuspecFileName := fmt.Sprintf("%s.%s", name, nuspecExt)
	path := filepath.Join(p.packagesDir, name, version, nuspecFileName)

	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %q file: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var pkg Package
	if err = xml.NewDecoder(f).Decode(&pkg); err != nil {
		return nil, xerrors.Errorf("unable to decode %q file: %w", path, err)
	}

	if license := pkg.Metadata.License; license.Type != "expression" || license.Text == "" {
		return nil, nil
	}
	return []types.License{
		{
			Name: pkg.Metadata.License.Text,
		},
	}, nil
}

func (p nuspecParser) findConcludedLicenses(name, version string) ([]types.License, error) {
	name, version = strings.ToLower(name), strings.ToLower(version)

	// package path uses lowercase letters only
	// e.g. `$HOME/.nuget/packages/newtonsoft.json/13.0.3/newtonsoft.json.nuspec`
	// for `Newtonsoft.Json` v13.0.3
	packagePath := filepath.Join(p.packagesDir, name, version)
	if !fsutils.DirExists(packagePath) {
		p.logger.Info(`To collect the license information of packages, "dotnet restore" needs to be performed beforehand`,
			log.String("dir", packagePath))
		return nil, nil
	}

	// get the package ID for given package name and version
	pkgID := dependency.ID(types.NuGet, name, version)

	walker, err := fsutils.NewRecursiveWalker(fsutils.RecursiveWalkerInput{
		Logger:                    p.logger,
		Parser:                    p,
		PackageManifestFile:       fmt.Sprintf("%s.%s", name, nuspecExt),
		PackageDependencyDir:      ".nuget/packages",
		ClassifierConfidenceLevel: p.licenseConfig.ClassifierConfidenceLevel,
		LicenseTextCacheDir:       p.licenseConfig.LicenseTextCacheDir,
		ParallelWorkers:           p.licenseConfig.LicenseScanWorkers,
	})
	if err != nil {
		return nil, err
	}

	// Start the worker pool which sends data to license classifier
	walker.StartWorkerPool()

	// get the file system rooted at given rootPath
	fsys := os.DirFS(p.packagesDir)
	p.logger.Debug("Created fsys rooted at root path", log.String("path", p.packagesDir))

	packagePath = path.Join(name, version)
	if ret, err := walker.Walk(fsys, packagePath, ""); !ret || err != nil {
		p.logger.Error("recursive walk has failed", log.String("dir", packagePath))
	}

	// exit the worker pool
	walker.StopWorkerPool()

	// get processed licenses
	licensesMap := walker.GetLicenses()

	// Update the License FilePath to absolute path
	for i := range licensesMap[pkgID] {
		license := &licensesMap[pkgID][i]
		if license.FilePath != "" {
			license.FilePath = filepath.Join(p.packagesDir, license.FilePath)
		}
	}

	return licensesMap[pkgID], nil
}

// finds licenses at the root path (".") relative to given file system fsys
func (p nuspecParser) findLicensesAtRootPath(fsys fs.FS) ([]types.License, error) {
	walker, err := fsutils.NewRecursiveWalker(fsutils.RecursiveWalkerInput{
		Logger:                    p.logger,
		Parser:                    p,
		PackageManifestFile:       fmt.Sprintf("%s.%s", "", nuspecExt),
		PackageDependencyDir:      ".nuget/packages",
		ClassifierConfidenceLevel: p.licenseConfig.ClassifierConfidenceLevel,
		LicenseTextCacheDir:       p.licenseConfig.LicenseTextCacheDir,
		ParallelWorkers:           p.licenseConfig.LicenseScanWorkers,
	})
	if err != nil {
		return nil, err
	}

	// Start the worker pool which sends data to license classifier
	walker.StartWorkerPool()

	if ret, err := walker.Walk(fsys, ".", ""); !ret || err != nil {
		p.logger.Error("recursive walk has failed", log.String("dir", "."))
		return nil, err
	}

	// exit the worker pool
	walker.StopWorkerPool()

	return walker.GetLicenses()[types.LOOSE_LICENSES], nil
}

func (p nuspecParser) ParseManifest(
	fsys fs.FS,
	path string,
) (types.PackageManifest, error) {
	fp, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	var pkg Package
	if err := xml.NewDecoder(fp).Decode(&pkg); err != nil {
		return nil, xerrors.Errorf("unable to decode nuspec manifest file: %w", err)
	}

	name, version := strings.ToLower(pkg.Metadata.Name), strings.ToLower(pkg.Metadata.Version)
	pkg.ID = dependency.ID(types.NuGet, name, version)

	return pkg, nil
}

func (p Package) PackageID() string {
	return p.ID
}

func (p Package) DeclaredLicenses() []types.License {
	var declaredLicenses = []types.License{{Name: p.Metadata.License.Text, IsDeclared: true}}
	return declaredLicenses
}
