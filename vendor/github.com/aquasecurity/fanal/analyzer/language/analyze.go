package language

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Analyze(fileType, filePath string, r dio.ReadSeekerAt, parser godeptypes.Parser) (*analyzer.AnalysisResult, error) {
	parsedLibs, parsedDependencies, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	// The file path of each library should be empty in case of dependency list such as lock file
	// since they all will be the same path.
	return ToAnalysisResult(fileType, filePath, "", parsedLibs, parsedDependencies), nil
}

func ToAnalysisResult(fileType, filePath, libFilePath string, libs []godeptypes.Library, deps []godeptypes.Dependency) *analyzer.AnalysisResult {
	if len(libs) == 0 {
		return nil
	}

	var pkgs []types.Package
	for _, lib := range libs {
		pkgs = append(pkgs, types.Package{
			ID:       lib.ID,
			Name:     lib.Name,
			Version:  lib.Version,
			FilePath: libFilePath,
			Indirect: lib.Indirect,
			License:  lib.License,
		})
	}
	apps := []types.Application{{
		Type:         fileType,
		FilePath:     filePath,
		Libraries:    pkgs,
		Dependencies: deps,
	}}

	return &analyzer.AnalysisResult{Applications: apps}
}
