package redhatbase

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"golang.org/x/xerrors"
)

const almaAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&almaOSAnalyzer{})
}

type almaOSAnalyzer struct{}

func (a almaOSAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("alma: invalid almalinux-release")
		}

		switch strings.ToLower(result[1]) {
		case "alma", "almalinux", "alma linux":
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alma, Name: result[2]},
			}, nil
		}
	}

	return nil, xerrors.Errorf("alma: %w", aos.AnalyzeOSError)
}

func (a almaOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a almaOSAnalyzer) requiredFiles() []string {
	return []string{"etc/almalinux-release"}
}

func (a almaOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlma
}

func (a almaOSAnalyzer) Version() int {
	return almaAnalyzerVersion
}
