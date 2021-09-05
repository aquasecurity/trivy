package pkg

import (
	"bytes"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
)

func init() {
	analyzer.RegisterAnalyzer(&nodePkgLibraryAnalyzer{})
}

const (
	version      = 1
	requiredFile = "package.json"
)

type nodePkgLibraryAnalyzer struct{}

// Analyze analyzes package.json for node packages
func (a nodePkgLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parsedLib, err := packagejson.Parse(bytes.NewReader(target.Content))
	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				Type:     types.NodePkg,
				FilePath: target.FilePath,
				Libraries: []types.LibraryInfo{
					{
						FilePath: target.FilePath,
						Library:  parsedLib,
					},
				},
			},
		},
	}, nil
}

func (a nodePkgLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return requiredFile == filepath.Base(filePath)
}

func (a nodePkgLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNodePkg
}

func (a nodePkgLibraryAnalyzer) Version() int {
	return version
}
