package packaging

import (
	"bytes"
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
		// egg
		".egg-info",
		".egg-info/PKG-INFO",

		// wheel
		".dist-info/METADATA",
	}
)

type packagingAnalyzer struct{}

// Analyze analyzes egg and wheel files.
func (a packagingAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	r := bytes.NewReader(target.Content)
	lib, err := packaging.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{Applications: []types.Application{
		{
			Type:     types.PythonPkg,
			FilePath: target.FilePath,
			Libraries: []types.LibraryInfo{
				{
					FilePath: target.FilePath,
					Library:  lib,
				},
			},
		},
	}}, nil
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
