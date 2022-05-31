package helm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"golang.org/x/xerrors"
)

const version = 1

const maxTarSize = 209_715_200 // 200MB

type ConfigAnalyzer struct {
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		filePattern: filePattern,
	}
}

func (a ConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	if isArchive(input.FilePath) {
		if !isHelmChart(input.FilePath, input.Content) {
			return nil, nil
		}
		// reset the content
		_, err := input.Content.Seek(0, 0)
		if err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// it will be passed to misconfig post handler
			types.MisconfPostHandler: {
				{
					Type:    types.Helm,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

func (a ConfigAnalyzer) Required(filePath string, info os.FileInfo) bool {
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	if info.Size() > maxTarSize {
		// tarball is too big to be Helm chart - move on
		return false
	}

	ext := filepath.Ext(filePath)
	for _, acceptable := range []string{".tpl", ".json", ".yaml", ".tar", ".tgz", ".tar.gz"} {
		if strings.EqualFold(ext, acceptable) {
			return true
		}
	}

	name := filepath.Base(filePath)
	for _, acceptable := range []string{"Chart.yaml", ".helmignore"} {
		if strings.EqualFold(name, acceptable) {
			return true
		}
	}

	return false
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHelm
}

func (ConfigAnalyzer) Version() int {
	return version
}

func isHelmChart(path string, file dio.ReadSeekerAt) bool {

	var err error
	var fr io.Reader = file

	if isGzip(path) {
		if fr, err = gzip.NewReader(file); err != nil {
			return false
		}
	}
	tr := tar.NewReader(fr)

	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false
		}

		if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "Chart.yaml") {
			return true
		}
	}
	return false
}

func isArchive(path string) bool {
	if strings.HasSuffix(path, ".tar") || isGzip(path) {
		return true
	}
	return false
}

func isGzip(path string) bool {
	if strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".tar.gz") {
		return true
	}
	return false
}
