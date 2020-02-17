package analyzer

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/image"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

var (
	osAnalyzers      []OSAnalyzer
	pkgAnalyzers     []PkgAnalyzer
	libAnalyzers     []LibraryAnalyzer
	commandAnalyzers []CommandAnalyzer
	additionalFiles  []string

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("Unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("Failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("No packages detected")
)

type Config struct {
	Extractor extractor.Extractor
}

type OSAnalyzer interface {
	Analyze(extractor.FileMap) (OS, error)
	RequiredFiles() []string
}

type PkgAnalyzer interface {
	Analyze(extractor.FileMap) ([]Package, error)
	RequiredFiles() []string
}

type CommandAnalyzer interface {
	Analyze(OS, extractor.FileMap) ([]Package, error)
	RequiredFiles() []string
}

type FilePath string

type LibraryAnalyzer interface {
	Analyze(extractor.FileMap) (map[FilePath][]godeptypes.Library, error)
	RequiredFiles() []string
}

type OS struct {
	Name   string
	Family string
}

type Package struct {
	Name       string
	Version    string
	Release    string
	Epoch      int
	Arch       string
	SrcName    string
	SrcVersion string
	SrcRelease string
	SrcEpoch   int
}

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

func RegisterOSAnalyzer(analyzer OSAnalyzer) {
	osAnalyzers = append(osAnalyzers, analyzer)
}

func RegisterPkgAnalyzer(analyzer PkgAnalyzer) {
	pkgAnalyzers = append(pkgAnalyzers, analyzer)
}

func RegisterCommandAnalyzer(analyzer CommandAnalyzer) {
	commandAnalyzers = append(commandAnalyzers, analyzer)
}

func RegisterLibraryAnalyzer(analyzer LibraryAnalyzer) {
	libAnalyzers = append(libAnalyzers, analyzer)
}

func AddRequiredFilenames(filenames []string) {
	additionalFiles = append(additionalFiles, filenames...)
}

func RequiredFilenames() []string {
	filenames := []string{}
	filenames = append(filenames, additionalFiles...)
	for _, analyzer := range osAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	for _, analyzer := range pkgAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	for _, analyzer := range libAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	return filenames
}

// TODO: Remove opts as they're no longer needed
func (ac Config) Analyze(ctx context.Context, imageName string, opts ...types.DockerOption) (fileMap extractor.FileMap, err error) {
	transports := []string{"docker-daemon:", "docker://"}
	ref := image.Reference{Name: imageName, IsFile: false}
	fileMap, err = ac.Extractor.Extract(ctx, ref, transports, RequiredFilenames())
	if err != nil {
		return nil, xerrors.Errorf("failed to extract files: %w", err)
	}
	return fileMap, nil
}

func (ac Config) AnalyzeFile(ctx context.Context, filePath string) (fileMap extractor.FileMap, err error) {
	transports := []string{"docker-archive:"}
	ref := image.Reference{Name: filePath, IsFile: true}
	fileMap, err = ac.Extractor.Extract(ctx, ref, transports, RequiredFilenames())
	if err != nil {
		return nil, xerrors.Errorf("failed to extract files: %w", err)
	}
	return fileMap, nil
}

func GetOS(filesMap extractor.FileMap) (OS, error) {
	for _, analyzer := range osAnalyzers {
		os, err := analyzer.Analyze(filesMap)
		if err != nil {
			continue
		}
		return os, nil
	}
	return OS{}, ErrUnknownOS

}

func GetPackages(filesMap extractor.FileMap) ([]Package, error) {
	for _, analyzer := range pkgAnalyzers {
		pkgs, err := analyzer.Analyze(filesMap)

		// Differentiate between a package manager not being found and another error
		if err != nil && err == ErrNoPkgsDetected {
			continue
		} else if err != nil {
			return nil, xerrors.Errorf("failed to get packages: %w", err)
		}
		return pkgs, nil
	}
	return nil, ErrPkgAnalysis
}

func GetPackagesFromCommands(targetOS OS, filesMap extractor.FileMap) ([]Package, error) {
	for _, analyzer := range commandAnalyzers {
		pkgs, err := analyzer.Analyze(targetOS, filesMap)
		if err != nil {
			continue
		}
		return pkgs, nil
	}
	return nil, nil
}

func CheckPackage(pkg *Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}

func GetLibraries(filesMap extractor.FileMap) (map[FilePath][]godeptypes.Library, error) {
	results := map[FilePath][]godeptypes.Library{}
	for _, analyzer := range libAnalyzers {
		libMap, err := analyzer.Analyze(filesMap)
		if err != nil {
			return nil, xerrors.Errorf("failed to get libraries: %w", err)
		}

		for filePath, libs := range libMap {
			results[filePath] = libs
		}
	}
	return results, nil
}
