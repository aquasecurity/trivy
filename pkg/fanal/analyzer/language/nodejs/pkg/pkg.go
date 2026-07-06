package pkg

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/lo"

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

func (*parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
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
func (a nodePkgLibraryAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.AnalyzePackage(ctx, types.NodePkg, input.FilePath, input.Content, &parser{}, input.Options.FileChecksum)
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

// IsPackageRoot reports whether the path is a top-level package.json of an
// installed npm package, rather than a subpath-helper file such as
// node_modules/rxjs/ajax/package.json (a bundler resolution hint with no
// version, not a real package). Paths outside node_modules pass through.
func IsPackageRoot(filePath string) bool {
	if filepath.Base(filePath) != requiredFile {
		return false
	}
	parts := strings.Split(filepath.ToSlash(filePath), "/")

	// Take the last "node_modules" as the reference point: in nested deps
	// (a/node_modules/b) and pnpm's virtual store
	// (.pnpm/<id>/node_modules/<name>), each package sits under its own
	// inner "node_modules", not the outer one.
	anchor := lo.LastIndexOf(parts, "node_modules")
	if anchor < 0 {
		return true
	}

	// Segments between the last "node_modules" and the trailing "package.json"
	// must form a single package-name shape, otherwise this is a subpath helper:
	//   1 segment, no "@" prefix          → unscoped package (rxjs)
	//   2 segments, first starts with "@" → scoped package   (@angular/core)
	//   anything else                     → subpath helper   (rxjs/ajax, @angular/core/testing)
	name := parts[anchor+1 : len(parts)-1]
	switch len(name) {
	case 1:
		return !strings.HasPrefix(name[0], "@")
	case 2:
		return strings.HasPrefix(name[0], "@")
	}
	return false
}
