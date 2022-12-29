package redhatbase

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"

	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const oracleAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&oracleOSAnalyzer{})
}

type oracleOSAnalyzer struct{}

func (a oracleOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("oracle: invalid oracle-release")
		}
		return &analyzer.AnalysisResult{
			OS: types.OS{Family: aos.Oracle, Name: result[2]},
		}, nil
	}

	return nil, xerrors.Errorf("oracle: %w", aos.AnalyzeOSError)
}

func (a oracleOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a oracleOSAnalyzer) requiredFiles() []string {
	return []string{"etc/oracle-release"}
}

func (a oracleOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeOracle
}

func (a oracleOSAnalyzer) Version() int {
	return oracleAnalyzerVersion
}
