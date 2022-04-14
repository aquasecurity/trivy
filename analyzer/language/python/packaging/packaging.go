package packaging

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/python/packaging"
)

func init() {
	analyzer.RegisterAnalyzer(&packagingAnalyzer{})
}

const version = 1

var (
	requiredFiles = []string{
		// .egg format
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg", // zip format
		"EGG-INFO/PKG-INFO",

		// .egg-info format: .egg-info can be a file or directory
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg-info",
		".egg-info/PKG-INFO",

		// wheel
		".dist-info/METADATA",
	}
)

type packagingAnalyzer struct{}

// Analyze analyzes egg and wheel files.
func (a packagingAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var r io.Reader = input.Content

	// .egg file is zip format and PKG-INFO needs to be extracted from the zip file.
	if strings.HasSuffix(input.FilePath, ".egg") {
		pkginfoInZip, err := a.analyzeEggZip(input.Content, input.Info.Size())
		if err != nil {
			return nil, xerrors.Errorf("egg analysis error: %w", err)
		}
		if pkginfoInZip == nil { // Egg archive may not contain required files, then we will get nil. Skip this archives
			return nil, nil
		}

		defer pkginfoInZip.Close()

		r = pkginfoInZip
	}

	lib, err := packaging.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{Applications: []types.Application{
		{
			Type:     types.PythonPkg,
			FilePath: input.FilePath,
			Libraries: []types.Package{
				{
					Name:     lib.Name,
					Version:  lib.Version,
					License:  lib.License,
					FilePath: input.FilePath,
				},
			},
		},
	}}, nil
}

func (a packagingAnalyzer) analyzeEggZip(r io.ReaderAt, size int64) (io.ReadCloser, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, xerrors.Errorf("zip reader error: %w", err)
	}

	for _, file := range zr.File {
		if !a.Required(file.Name, nil) {
			continue
		}

		return a.open(file)
	}

	return nil, nil
}

func (a packagingAnalyzer) open(file *zip.File) (io.ReadCloser, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (a packagingAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// For Windows
	filePath = filepath.ToSlash(filePath)

	for _, r := range requiredFiles {
		if strings.HasSuffix(filePath, r) {
			return true
		}
	}
	return false
}

func (a packagingAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkg
}

func (a packagingAnalyzer) Version() int {
	return version
}
