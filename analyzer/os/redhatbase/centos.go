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

func init() {
	analyzer.RegisterAnalyzer(&centOSAnalyzer{})
}

var (
	requiredFiles = []string{"etc/centos-release"}
)

type centOSAnalyzer struct{}

func (a centOSAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("centos: invalid centos-release")
		}

		switch strings.ToLower(result[1]) {
		case "centos", "centos linux":
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.CentOS, Name: result[2]},
			}, nil
		}
	}

	return nil, xerrors.Errorf("centos: %w", aos.AnalyzeOSError)
}

func (a centOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a centOSAnalyzer) requiredFiles() []string {
	return []string{"etc/centos-release"}
}

func (a centOSAnalyzer) Name() string {
	return aos.CentOS
}
