package pkg

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&nodePkgLibraryAnalyzer{})
}

const (
	version      = 1
	requiredFile = "package.json"
)

type parser struct{}

func (*parser) Parse(r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	p := packagejson.NewParser()
	pkg, err := p.Parse(r)
	if err != nil {
		return nil, nil, err
	}
	// skip packages without name/version
	if pkg.Package.ID == "" {
		return nil, nil, nil
	}
	// package.json may contain version range in `dependencies` fields
	// e.g.   "devDependencies": { "mocha": "^5.2.0", }
	// so we get only information about project
	return []types.Package{pkg.Package}, nil, nil
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
