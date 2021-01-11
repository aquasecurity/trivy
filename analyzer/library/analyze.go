package library

import (
	"bytes"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Analyze(analyzerType, filePath string, content []byte, parse func(r io.Reader) ([]godeptypes.Library, error)) (
	*analyzer.AnalysisResult, error) {
	r := bytes.NewBuffer(content)
	parsedLibs, err := parse(r)
	if err != nil {
		return nil, xerrors.Errorf("error with a lock file: %w", err)
	}

	var libs []types.LibraryInfo
	for _, lib := range parsedLibs {
		libs = append(libs, types.LibraryInfo{
			Library: lib,
		})
	}
	apps := []types.Application{{
		Type:      analyzerType,
		FilePath:  filePath,
		Libraries: libs,
	}}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}
