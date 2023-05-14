package pkg

import (
	"context"
	"os"
	"path/filepath"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&nodePkgLibraryAnalyzer{})
}

const (
	version      = 1
	requiredFile = "package.json"
)

type parser struct{}

func (*parser) Parse(r dio.ReadSeekerAt) ([]godeptypes.Library, []godeptypes.Dependency, error) {
	p := packagejson.NewParser()
	pkg, err := p.Parse(r)
	if err != nil {
		return nil, nil, err
	}
	// package.json may contain version range in `dependencies` fields
	// e.g.   "devDependencies": { "mocha": "^5.2.0", }
	// so we get only information about project
	return []godeptypes.Library{pkg.Library}, nil, nil
}

type nodePkgLibraryAnalyzer struct{}

// Analyze analyzes package.json for node packages
func (a nodePkgLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.AnalyzePackage(types.NodePkg, input.FilePath, input.Content, &parser{}, input.Options.FileChecksum)
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
