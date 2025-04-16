package redhatbase

import (
	"bufio"
	"context"
	"os"
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const fedoraAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&fedoraOSAnalyzer{})
}

type fedoraOSAnalyzer struct{}

func (a fedoraOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("fedora: Invalid fedora-release")
		}

		switch strings.ToLower(result[1]) {
		case "fedora", "fedora linux":
			return &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Fedora,
					Name:   result[2],
				},
			}, nil
		}
	}
	return nil, xerrors.Errorf("fedora: %w", fos.AnalyzeOSError)
}

func (a fedoraOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(a.requiredFiles(), filePath)
}

func (a fedoraOSAnalyzer) requiredFiles() []string {
	return []string{
		"etc/fedora-release",
		"usr/lib/fedora-release",
	}
}

func (a fedoraOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeFedora
}

func (a fedoraOSAnalyzer) Version() int {
	return fedoraAnalyzerVersion
}

// StaticPaths returns the static paths of the fedora analyzer
func (a fedoraOSAnalyzer) StaticPaths() []string {
	return a.requiredFiles()
}
