package analyzer

import (
	"context"
	"io"
	"time"

	"github.com/knqyf263/fanal/extractor"
	"github.com/pkg/errors"
)

var (
	osAnalyzers  []OSAnalyzer
	pkgAnalyzers []PkgAnalyzer

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = errors.New("Unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = errors.New("Failed to analyze packages")
)

type OSAnalyzer interface {
	Analyze(extractor.FileMap) (OS, error)
	RequiredFiles() []string
}

type PkgAnalyzer interface {
	Analyze(extractor.FileMap) ([]Package, error)
	RequiredFiles() []string
}

type OS struct {
	Name   string
	Family string
}

type Package struct {
	Name    string
	Version string
	Release string
	Epoch   int
	Type    string
}

var (
	TypeBinary = "binary"
	TypeSource = "source"
)

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

func RequiredFilenames() []string {
	filenames := []string{}
	for _, analyzer := range osAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	for _, analyzer := range pkgAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	return filenames
}

func Analyze(ctx context.Context, imageName string) (filesMap extractor.FileMap, err error) {
	e := extractor.NewDockerExtractor(extractor.DockerOption{Timeout: 600 * time.Second})
	filesMap, err = e.Extract(ctx, imageName, RequiredFilenames())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to extract files")
	}
	return filesMap, nil
}

func AnalyzeFromFile(ctx context.Context, r io.ReadCloser) (filesMap extractor.FileMap, err error) {
	e := extractor.NewDockerExtractor(extractor.DockerOption{})
	filesMap, err = e.ExtractFromFile(ctx, r, RequiredFilenames())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to extract files")
	}
	return filesMap, nil
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
		if err != nil {
			continue
		}
		return pkgs, nil
	}
	return nil, ErrUnknownOS
}

func CheckPackage(pkg *Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}
