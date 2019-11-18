package analyzer

import (
	"context"
	"io"
	"testing"

	"github.com/aquasecurity/fanal/extractor"

	"github.com/stretchr/testify/assert"
)

type mockDockerExtractor struct {
	saveLocalImage  func(ctx context.Context, imageName string) (io.Reader, error)
	extractFromFile func(ctx context.Context, r io.Reader, filenames []string) (extractor.FileMap, error)
}

func (mde mockDockerExtractor) Extract(ctx context.Context, imageName string, filenames []string) (extractor.FileMap, error) {
	panic("implement me")
}

func (mde mockDockerExtractor) ExtractFromFile(ctx context.Context, r io.Reader, filenames []string) (extractor.FileMap, error) {
	if mde.extractFromFile != nil {
		return mde.extractFromFile(ctx, r, filenames)
	}
	return extractor.FileMap{}, nil
}

func (mde mockDockerExtractor) SaveLocalImage(ctx context.Context, imageName string) (io.Reader, error) {
	if mde.saveLocalImage != nil {
		return mde.saveLocalImage(ctx, imageName)
	}
	return nil, nil
}

func (mde mockDockerExtractor) ExtractFiles(layer io.Reader, filenames []string) (extractor.FileMap, extractor.OPQDirs, error) {
	panic("implement me")
}

func TestAnalyze(t *testing.T) {
	ac := AnalyzerConfig{Extractor: mockDockerExtractor{}}
	fm, err := ac.Analyze(context.TODO(), "foo")
	assert.NoError(t, err)
	assert.NotNil(t, fm)
}
