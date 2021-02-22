package debian

import (
	"bufio"
	"bytes"
	"os"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&debianOSAnalyzer{})
}

var requiredFiles = []string{"etc/debian_version"}

type debianOSAnalyzer struct{}

func (a debianOSAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	for scanner.Scan() {
		line := scanner.Text()
		return &analyzer.AnalysisResult{
			OS: &types.OS{Family: aos.Debian, Name: line},
		}, nil
	}
	return nil, xerrors.Errorf("debian: %w", aos.AnalyzeOSError)
}

func (a debianOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a debianOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDebian
}
