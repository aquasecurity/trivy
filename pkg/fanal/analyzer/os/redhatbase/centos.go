package redhatbase

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

const centosAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&centOSAnalyzer{})
}

type centOSAnalyzer struct{}

func (a centOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, errors.New("centos: invalid centos-release")
		}

		switch strings.ToLower(result[1]) {
		case "centos", "centos linux":
			return &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.CentOS,
					Name:   result[2],
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("centos: %w", fos.AnalyzeOSError)
}

func (a centOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a centOSAnalyzer) requiredFiles() []string {
	return []string{"etc/centos-release"}
}

func (a centOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCentOS
}

func (a centOSAnalyzer) Version() int {
	return centosAnalyzerVersion
}
