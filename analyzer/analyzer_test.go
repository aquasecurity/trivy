package analyzer

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aquasecurity/fanal/extractor"

	"github.com/stretchr/testify/assert"
)

type mockDockerExtractor struct {
	saveLocalImage  func(ctx context.Context, imageName string) (io.Reader, error)
	extractFromFile func(ctx context.Context, r io.Reader, filenames []string) (extractor.FileMap, error)
	extract         func(ctx context.Context, imageName string, filenames []string) (extractor.FileMap, error)
}

func (mde mockDockerExtractor) Extract(ctx context.Context, imageName string, filenames []string) (extractor.FileMap, error) {
	if mde.extract != nil {
		return mde.extract(ctx, imageName, filenames)
	}
	return extractor.FileMap{}, nil
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

type mockOSAnalyzer struct{}

func (m mockOSAnalyzer) Analyze(extractor.FileMap) (OS, error) {
	panic("implement me")
}

func (m mockOSAnalyzer) RequiredFiles() []string {
	return []string{"file1", "file2"}
}

func TestAnalyze(t *testing.T) {
	testCases := []struct {
		name                string
		saveLocalImageFunc  func(ctx context.Context, imageName string) (io.Reader, error)
		extractFunc         func(ctx context.Context, imageName string, filenames []string) (extractor.FileMap, error)
		extractFromFileFunc func(ctx context.Context, r io.Reader, filenames []string) (maps extractor.FileMap, e error)
		expectedError       error
		expectedFileMap     extractor.FileMap
	}{
		{
			name: "happy path with docker installed and image found",
			extractFromFileFunc: func(ctx context.Context, r io.Reader, filenames []string) (maps extractor.FileMap, e error) {
				assert.Equal(t, []string{"file1", "file2"}, filenames)
				return extractor.FileMap{
					"file1": []byte{0x1, 0x2, 0x3},
					"file2": []byte{0x4, 0x5, 0x6},
				}, nil
			},
			expectedFileMap: extractor.FileMap{
				"file1": []byte{0x1, 0x2, 0x3},
				"file2": []byte{0x4, 0x5, 0x6},
			},
		},
		{
			name: "happy path with no docker installed or no image found",
			saveLocalImageFunc: func(ctx context.Context, imageName string) (reader io.Reader, e error) {
				return nil, errors.New("couldn't save local image")
			},
			extractFunc: func(ctx context.Context, imageName string, filenames []string) (maps extractor.FileMap, e error) {
				assert.Equal(t, "fooimage", imageName)
				assert.Equal(t, []string{"file1", "file2"}, filenames)
				return extractor.FileMap{
					"file1": []byte{0x1, 0x2, 0x3},
					"file2": []byte{0x4, 0x5, 0x6},
				}, nil
			},
			expectedFileMap: extractor.FileMap{
				"file1": []byte{0x1, 0x2, 0x3},
				"file2": []byte{0x4, 0x5, 0x6},
			},
		},
	}

	for _, tc := range testCases {
		RegisterOSAnalyzer(mockOSAnalyzer{})

		ac := AnalyzerConfig{Extractor: mockDockerExtractor{
			extractFromFile: tc.extractFromFileFunc,
			extract:         tc.extractFunc,
			saveLocalImage:  tc.saveLocalImageFunc,
		}}
		fm, err := ac.Analyze(context.TODO(), "fooimage")
		assert.Equal(t, tc.expectedError, err, tc.name)
		assert.Equal(t, tc.expectedFileMap, fm, tc.name)

		// reset the gnarly global state
		osAnalyzers = []OSAnalyzer{}
	}
}
