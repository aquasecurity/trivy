package packaging

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePythonPkg, newPackagingAnalyzer)
}

const version = 2

func newPackagingAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &packagingAnalyzer{
		logger:                           log.WithPrefix("python"),
		pkgParser:                        packaging.NewParser(),
		licenseClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
	}, nil
}

var (
	eggFiles = []string{
		// .egg format
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		// ".egg" is zip format. We check it in `eggAnalyzer`.
		"EGG-INFO/PKG-INFO",

		// .egg-info format: .egg-info can be a file or directory
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg-info",
		".egg-info/PKG-INFO",
		// https://github.com/aquasecurity/trivy/issues/9171
		".egg-info/METADATA",
	}
)

type packagingAnalyzer struct {
	logger                           *log.Logger
	pkgParser                        language.Parser
	licenseClassifierConfidenceLevel float64
}

// PostAnalyze analyzes egg and wheel files.
func (a packagingAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {

	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == "METADATA" || isEggFile(path) || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}

		app, err := a.parse(ctx, filePath, rsa, input.Options.FileChecksum)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		if err = a.mergeSBOMs(ctx, input.FS, path.Dir(filePath), app); err != nil {
			a.logger.Debug("Packaging Analyzer- SBOM files merge error", log.FilePath(filePath), log.Err(err))
		}

		opener := func(licPath string) (io.ReadCloser, error) {
			// Note that fs.FS is always slashed regardless of the platform,
			// and path.Join should be used rather than filepath.Join.
			f, err := input.FS.Open(path.Join(path.Dir(filePath), licPath))
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			} else if err != nil {
				return nil, xerrors.Errorf("file open error: %w", err)
			}
			return f, nil
		}

		if err = fillAdditionalData(opener, app, a.licenseClassifierConfidenceLevel); err != nil {
			a.logger.Warn("Unable to collect additional info", log.Err(err))
		}

		apps = append(apps, *app)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("python package walk error: %w", err)
	}
	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a packagingAnalyzer) mergeSBOMs(ctx context.Context, fsys fs.FS, distInfoDir string, app *types.Application) error {
	sbomDir := path.Join(distInfoDir, "sboms")
	entries, err := fs.ReadDir(fsys, sbomDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return xerrors.Errorf("unable to read sboms directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !sbom.IsSBOMFile(entry.Name()) {
			continue
		}

		sbomPath := path.Join(sbomDir, entry.Name())
		if err := a.parseAndMergeSBOM(ctx, fsys, sbomPath, app); err != nil {
			a.logger.Debug("Failed to merge python SBOM files", log.FilePath(sbomPath), log.Err(err))
			continue
		}
	}
	return nil
}

func (a packagingAnalyzer) parseAndMergeSBOM(ctx context.Context, fsys fs.FS, sbomPath string, app *types.Application) error {
	f, err := fsys.Open(sbomPath)
	if err != nil {
		return xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	rsa, err := xio.NewReadSeekerAt(f)
	if err != nil {
		return xerrors.Errorf("reader error: %w", err)
	}

	format, err := sbom.DetectFormat(rsa)
	if err != nil {
		return xerrors.Errorf("failed to detect SBOM format: %w", err)
	}

	if _, err = rsa.Seek(0, io.SeekStart); err != nil {
		return xerrors.Errorf("unable to seek: %w", err)
	}

	bom, err := sbom.Decode(ctx, rsa, format)
	if err != nil {
		return xerrors.Errorf("SBOM decode error: %w", err)
	}

	// Merge packages from both Packages and Applications in the SBOM
	for _, pkgInfo := range bom.Packages {
		for _, pkg := range pkgInfo.Packages {
			a.mergePackage(pkg, app)
		}
	}
	for _, bomApp := range bom.Applications {
		for _, pkg := range bomApp.Packages {
			a.mergePackage(pkg, app)
		}
	}

	return nil
}

func (a packagingAnalyzer) mergePackage(sbomPkg types.Package, app *types.Application) {
	// Remove file_name qualifier from PURL
	if sbomPkg.Identifier.PURL != nil {
		var quals []packageurl.Qualifier
		for _, q := range sbomPkg.Identifier.PURL.Qualifiers {
			if q.Key != "file_name" {
				quals = append(quals, q)
			}
		}
		sbomPkg.Identifier.PURL.Qualifiers = quals
	}

	if len(app.Packages) == 0 {
		return
	}
	pyPkg := &app.Packages[0] // Main package from METADATA

	//  Identify if this is the main Python package
	if python.NormalizePkgName(sbomPkg.Name, true) == python.NormalizePkgName(pyPkg.Name, true) &&
		sbomPkg.Version == pyPkg.Version {
		// Merge dependencies from this SBOM file into the main package
		pyPkg.DependsOn = lo.Uniq(append(pyPkg.DependsOn, sbomPkg.DependsOn...))
		// Update to the canonical PURL
		pyPkg.Identifier.PURL = sbomPkg.Identifier.PURL
		return
	}

	// Otherwise, it's a bundled library or a separate dependency
	// Check if we've already added this package from a previous SBOM file in the same folder
	exists := lo.SomeBy(app.Packages, func(p types.Package) bool {
		return p.Name == sbomPkg.Name && p.Version == sbomPkg.Version
	})

	if !exists {
		app.Packages = append(app.Packages, sbomPkg)
	}
}

type fileOpener func(filePath string) (io.ReadCloser, error)

func fillAdditionalData(opener fileOpener, app *types.Application, licenseClassifierConfidenceLevel float64) error {
	for i, pkg := range app.Packages {
		var licenses []string
		for _, lic := range pkg.Licenses {
			// Parser adds `file://` prefix to filepath from `License-File` field
			// We need to read this file to find licenses
			// Otherwise, this is the name of the license
			if !strings.HasPrefix(lic, licensing.LicenseFilePrefix) {
				licenses = append(licenses, lic)
				continue
			}
			licensePath := path.Base(strings.TrimPrefix(lic, licensing.LicenseFilePrefix))

			foundLicenses, err := classifyLicenses(opener, licensePath, licenseClassifierConfidenceLevel)
			if err != nil {
				return xerrors.Errorf("unable to classify licenses: %w", err)
			}
			licenses = append(licenses, foundLicenses...)
		}
		app.Packages[i].Licenses = licenses
	}

	return nil
}

func classifyLicenses(opener fileOpener, licPath string, licenseClassifierConfidenceLevel float64) ([]string, error) {
	f, err := opener(licPath)
	if err != nil {
		return nil, xerrors.Errorf("unable to open license file: %w", err)
	} else if f == nil { // File doesn't exist
		return nil, nil
	}
	defer f.Close()

	l, err := licensing.Classify("", f, licenseClassifierConfidenceLevel)
	if err != nil {
		return nil, xerrors.Errorf("license classify error: %w", err)
	} else if l == nil { // No licenses found
		return nil, nil
	}

	// License found
	return xslices.Map(l.Findings, func(finding types.LicenseFinding) string {
		return finding.Name
	}), nil
}

func (a packagingAnalyzer) parse(ctx context.Context, filePath string, r xio.ReadSeekerAt, checksum bool) (*types.Application, error) {
	return language.ParsePackage(ctx, types.PythonPkg, filePath, r, a.pkgParser, checksum)
}

func (a packagingAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.Contains(filePath, ".dist-info") || isEggFile(filePath)
}

func isEggFile(filePath string) bool {
	return lo.SomeBy(eggFiles, func(fileName string) bool {
		return strings.HasSuffix(filePath, fileName)
	})
}

func (a packagingAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkg
}

func (a packagingAnalyzer) Version() int {
	return version
}
