package redhatbase

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"golang.org/x/xerrors"
)

const rockyAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&rockyOSAnalyzer{})
}

type rockyOSAnalyzer struct{}

func (a rockyOSAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("rocky: invalid rocky-release")
		}

		switch strings.ToLower(result[1]) {
		case "rocky", "rocky linux":
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Rocky, Name: result[2]},
			}, nil
		}
	}

	return nil, xerrors.Errorf("rocky: %w", aos.AnalyzeOSError)
}

func (a rockyOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a rockyOSAnalyzer) requiredFiles() []string {
	return []string{"etc/rocky-release"}
}

func (a rockyOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRocky
}

func (a rockyOSAnalyzer) Version() int {
	return rockyAnalyzerVersion
}
