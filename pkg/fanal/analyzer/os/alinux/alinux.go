package alinux

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"slices"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&alinuxOSAnalyzer{})
}

const version = 1

var (
	requiredFiles = []string{
		"etc/alinux-release",
		"etc/system-release",
	}
	alinuxRe = regexp.MustCompile(`Alibaba Cloud Linux.*release (\d[\d.]*)`)
)

type alinuxOSAnalyzer struct{}

func (a alinuxOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	foundOS, err := a.parseRelease(input.Content)
	if err != nil {
		return nil, err
	}
	return &analyzer.AnalysisResult{
		OS: foundOS,
	}, nil
}

func (a alinuxOSAnalyzer) parseRelease(r io.Reader) (types.OS, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		result := alinuxRe.FindStringSubmatch(line)
		if len(result) == 2 {
			return types.OS{
				Family: types.Alinux,
				Name:   result[1],
			}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("alinux: %w", fos.AnalyzeOSError)
}

func (a alinuxOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a alinuxOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlinux
}

func (a alinuxOSAnalyzer) Version() int {
	return version
}

// StaticPaths returns the static paths of the alinux analyzer
func (a alinuxOSAnalyzer) StaticPaths() []string {
	return requiredFiles
}
