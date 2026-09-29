package amazonlinux

import (
	"bufio"
	"context"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&amazonlinuxOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"etc/system-release",     // for 1 and 2 versions
	"usr/lib/system-release", // for 2022, 2023 version
}

type amazonlinuxOSAnalyzer struct{}

func (a amazonlinuxOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	foundOS, err := a.parseRelease(input.Content)
	if err != nil {
		return nil, err
	}
	return &analyzer.AnalysisResult{
		OS: foundOS,
	}, nil
}

func (a amazonlinuxOSAnalyzer) parseRelease(r io.Reader) (types.OS, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// Only Amazon Linux Prefix
		if strings.HasPrefix(line, "Amazon Linux release 2") {
			if len(fields) < 5 {
				continue
			}
			return types.OS{
				Family: types.Amazon,
				Name:   strings.Join(fields[3:], " "),
			}, nil
		} else if strings.HasPrefix(line, "Amazon Linux") {
			return types.OS{
				Family: types.Amazon,
				Name:   strings.Join(fields[2:], " "),
			}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("amazon: %w", fos.AnalyzeOSError)
}

func (a amazonlinuxOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a amazonlinuxOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAmazon
}

func (a amazonlinuxOSAnalyzer) Version() int {
	return version
}

// StaticPaths returns the static paths of the amazonlinux analyzer
func (a amazonlinuxOSAnalyzer) StaticPaths() []string {
	return requiredFiles
}
