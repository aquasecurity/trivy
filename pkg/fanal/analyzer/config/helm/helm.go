package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&helmConfigAnalyzer{})
}

const version = 1

const maxTarSize = 209_715_200 // 200MB

type helmConfigAnalyzer struct{}

func (a helmConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	isAnArchive := false
	if isArchive(input.FilePath) {
		isAnArchive = true
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
	if !isAnArchive {
		// if it's not an archive we need to remove the carriage returns
		b = bytes.ReplaceAll(b, []byte("\r"), []byte(""))
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

func (a helmConfigAnalyzer) Required(filePath string, info os.FileInfo) bool {
	if info.Size() > maxTarSize {
		// tarball is too big to be Helm chart - move on
		return false
	}

	for _, acceptable := range []string{".tpl", ".json", ".yml", ".yaml", ".tar", ".tgz", ".tar.gz"} {
		if strings.HasSuffix(strings.ToLower(filePath), acceptable) {
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

func (helmConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHelm
}

func (helmConfigAnalyzer) Version() int {
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
