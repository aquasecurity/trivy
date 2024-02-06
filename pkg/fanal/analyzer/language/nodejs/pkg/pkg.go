package pkg

import (
	"context"
	//"fmt"
	//	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterAnalyzer(&nodePkgLibraryAnalyzer{})
	analyzer.RegisterPostAnalyzer(analyzer.TypeNodePkg, newNodePkgLibraryAnalyzer)
}

const (
	version      = 1
	requiredFile = "package.json"
)

type parser struct{}

func newNodePkgLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &nodePkgLibraryAnalyzer{}, nil
}

func (*parser) Parse(r dio.ReadSeekerAt) ([]godeptypes.Library, []godeptypes.Dependency, error) {
	p := packagejson.NewParser()
	pkg, err := p.Parse(r)
	if err != nil {
		return nil, nil, err
	}
	// skip packages without name/version
	if pkg.Library.ID == "" {
		return nil, nil, nil
	}
	// package.json may contain version range in `dependencies` fields
	// e.g.   "devDependencies": { "mocha": "^5.2.0", }
	// so we get only information about project
	return []godeptypes.Library{pkg.Library}, nil, nil
}

type nodePkgLibraryAnalyzer struct{}

// Analyze analyzes package.json for node packages
func (a nodePkgLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	if requiredFile == filepath.Base(input.FilePath) {
		return language.AnalyzePackage(types.NodePkg, input.FilePath, input.Content, &parser{}, input.Options.FileChecksum)
	}
	return &analyzer.AnalysisResult{}, nil
}

func (a nodePkgLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return requiredFile == filepath.Base(filePath) || strings.Contains(filePath, "node_modules")
}

func (a nodePkgLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNodePkg
}

func (a nodePkgLibraryAnalyzer) Version() int {
	return version
}

func (a nodePkgLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// Parse package-lock.json
	required := func(path string, _ fs.DirEntry) bool {
		return strings.Contains(path, "node_modules")
	}
	files := make([]string, 0)
	fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		// Find all licenses from package.json files under node_modules dirs
		files = append(files, filePath)
		return nil
	})
	if len(files) == 0 {
		return &analyzer.AnalysisResult{}, nil
	}
	return &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				FilePath: "test",
				Libraries: []types.Package{
					{
						InstalledFiles: files,
					},
				},
			},
		},
	}, nil
}
