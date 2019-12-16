package analyzer

import (
	"context"
	"errors"
	"io"
	"os"
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

func TestConfig_Analyze(t *testing.T) {
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

	// cleanup global state from other tests
	commandAnalyzers = []CommandAnalyzer{}
	pkgAnalyzers = []PkgAnalyzer{}
	osAnalyzers = []OSAnalyzer{}
	libAnalyzers = []LibraryAnalyzer{}

	for _, tc := range testCases {
		RegisterOSAnalyzer(mockOSAnalyzer{})

		ac := Config{Extractor: mockDockerExtractor{
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

func TestConfig_AnalyzeFile(t *testing.T) {
	testCases := []struct {
		name                string
		extractFromFileFunc func(ctx context.Context, r io.Reader, filenames []string) (fileMap extractor.FileMap, err error)
		inputFile           string
		expectedError       error
		expectedFileMap     extractor.FileMap
	}{
		{
			name:            "happy path, valid tar.gz file",
			inputFile:       "testdata/alpine.tar.gz",
			expectedFileMap: extractor.FileMap{},
		},
		{
			name:            "happy path, valid tar file",
			expectedFileMap: extractor.FileMap{},
			inputFile:       "../utils/testdata/test.tar",
		},
		{
			name:          "sad path, valid file but ExtractFromFile fails",
			expectedError: errors.New("failed to extract files from tar: extract from file failed"),
			extractFromFileFunc: func(ctx context.Context, r io.Reader, filenames []string) (fileMap extractor.FileMap, err error) {
				return nil, errors.New("extract from file failed")
			},
		},
	}

	for _, tc := range testCases {
		ac := Config{
			Extractor: mockDockerExtractor{
				extractFromFile: tc.extractFromFileFunc,
			},
		}

		f, _ := os.Open(tc.inputFile)
		defer f.Close()
		fm, err := ac.AnalyzeFile(context.TODO(), f)
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
		assert.Equal(t, tc.expectedFileMap, fm, tc.name)
	}

}
