package redhatbase

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/aquasecurity/fanal/utils"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&oracleOSAnalyzer{})
}

type oracleOSAnalyzer struct{}

func (a oracleOSAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("oracle: invalid oracle-release")
		}
		return &analyzer.AnalysisResult{
			OS: &types.OS{Family: aos.Oracle, Name: result[2]},
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
