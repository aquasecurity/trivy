package packaging

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/python/packaging"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePythonPkg, newPackagingAnalyzer)
}

const version = 1

func newPackagingAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &packagingAnalyzer{
		pkgParser:                        packaging.NewParser(),
		licenseClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
	}, nil
}

var (
	eggFiles = []string{
		// .egg format
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg", // zip format
		"EGG-INFO/PKG-INFO",

		// .egg-info format: .egg-info can be a file or directory
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg-info",
		".egg-info/PKG-INFO",
	}
)

type packagingAnalyzer struct {
	pkgParser                        godeptypes.Parser
	licenseClassifierConfidenceLevel float64
}

// PostAnalyze analyzes egg and wheel files.
func (a packagingAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {

	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == "METADATA" || filepath.Base(path) == "RECORD" || isEggFile(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(dio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}
		//docker run jupyter/base-notebook:latest
		if strings.HasSuffix(path, "RECORD") {
			is := a.fillInstalledFiles(path, r)
			for _, app := range apps {
				if app.FilePath == strings.Replace(path, "RECORD", "METADATA", 1) {
					updateInstalledFiles(&app, is)
				}
			}
		}
		// .egg file is zip format and PKG-INFO needs to be extracted from the zip file.
		if strings.HasSuffix(path, ".egg") {
			info, err := d.Info()
			if err != nil {
				return xerrors.Errorf("egg file error: %w", err)
			}
			pkginfoInZip, err := a.analyzeEggZip(rsa, info.Size())
			if err != nil {
				return xerrors.Errorf("egg analysis error: %w", err)
			}

			// Egg archive may not contain required files, then we will get nil. Skip this archives
			if pkginfoInZip == nil {
				return nil
			}
			rsa = pkginfoInZip
		}

		app, err := a.parse(path, rsa, input.Options.FileChecksum)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		if err := a.fillAdditionalData(input.FS, app); err != nil {
			log.Logger.Warnf("Unable to collect additional info: %s", err)
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

func (a packagingAnalyzer) fillAdditionalData(fsys fs.FS, app *types.Application) error {
	for i, lib := range app.Libraries {
		var licenses []string
		for _, lic := range lib.Licenses {
			// Parser adds `file://` prefix to filepath from `License-File` field
			// We need to read this file to find licenses
			// Otherwise, this is the name of the license
			if !strings.HasPrefix(lic, "file://") {
				licenses = append(licenses, lic)
				continue
			}
			licenseFilePath := path.Base(strings.TrimPrefix(lic, "file://"))

			findings, err := classifyLicense(app.FilePath, licenseFilePath, a.licenseClassifierConfidenceLevel, fsys)
			if err != nil {
				return err
			} else if len(findings) == 0 {
				continue
			}

			// License found
			foundLicenses := lo.Map(findings, func(finding types.LicenseFinding, _ int) string {
				return finding.Name
			})
			licenses = append(licenses, foundLicenses...)
		}
		app.Libraries[i].Licenses = licenses
	}

	return nil
}

func updateInstalledFiles(app *types.Application, installedFiles []string) {
	for i, lib := range app.Libraries {
		app.Libraries[i].InstalledFiles = append(lib.InstalledFiles, installedFiles...)
	}
}

func (a packagingAnalyzer) fillInstalledFiles(filePath string, data io.Reader) []string {
	packagesLocation := "site-packages"
	installedFiles := []string{}
	index := strings.Index(filePath, "site-packages/")
	if index == -1 {
		index = strings.Index(filePath, "dist-packages/")
		packagesLocation = "dist-packages"
	}
	if index != -1 {
		basePath := filePath[:index] + packagesLocation /*  */
		scanner := bufio.NewScanner(data)
		// optionally, resize scanner's capacity for lines over 64K, see next example
		for scanner.Scan() {
			tBasePath := basePath
			line := scanner.Text()
			pkgLib := strings.Split(line, ",")
			if len(pkgLib) > 1 {
				dep := pkgLib[0]
				if strings.HasPrefix(dep, "..") {
					c := strings.Count(dep, "..")
					for i := 0; i < c; i++ {
						tBasePath = path.Dir(tBasePath)
					}
					newDep := strings.ReplaceAll(dep, "../", "")
					dep = newDep
				}
				fullPath := fmt.Sprintf("/%s/%s", tBasePath, dep)
				if strings.Contains(fullPath, ".cpython") && strings.HasSuffix(fullPath, ".pyc") {
					index := strings.Index(fullPath, ".cpython")
					re := regexp.MustCompile("[0-9]+")
					parts := re.FindAllString(fullPath[index:], -1)
					if len(parts) > 0 {
						fullPath = strings.ReplaceAll(fullPath, parts[0], "311")
					}
				}
				installedFiles = append(installedFiles, fullPath)
			}
		}
	}
	return installedFiles
}

func classifyLicense(dir, licPath string, classifierConfidenceLevel float64, fsys fs.FS) (types.LicenseFindings, error) {
	// Note that fs.FS is always slashed regardless of the platform,
	// and path.Join should be used rather than filepath.Join.
	f, err := fsys.Open(path.Join(path.Dir(dir), licPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	l, err := licensing.Classify(licPath, f, classifierConfidenceLevel)
	if err != nil {
		return nil, xerrors.Errorf("license classify error: %w", err)
	} else if l == nil {
		return nil, nil
	}

	return l.Findings, nil
}

func (a packagingAnalyzer) parse(filePath string, r dio.ReadSeekerAt, checksum bool) (*types.Application, error) {
	return language.ParsePackage(types.PythonPkg, filePath, r, a.pkgParser, checksum)
}

func (a packagingAnalyzer) analyzeEggZip(r io.ReaderAt, size int64) (dio.ReadSeekerAt, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, xerrors.Errorf("zip reader error: %w", err)
	}

	found, ok := lo.Find(zr.File, func(f *zip.File) bool {
		return isEggFile(f.Name)
	})
	if !ok {
		return nil, nil
	}
	return a.open(found)
}

// open reads the file content in the zip archive to make it seekable.
func (a packagingAnalyzer) open(file *zip.File) (dio.ReadSeekerAt, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, xerrors.Errorf("file %s open error: %w", file.Name, err)
	}

	return bytes.NewReader(b), nil
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
