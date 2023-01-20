package alt

import (
	"bufio"
	"context"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"golang.org/x/xerrors"
	"os"
	"strings"
)

const altAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&altOSAnalyzer{})
}

type altOSAnalyzer struct{}

func (a altOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var id, versionID string
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()

		ss := strings.SplitN(line, "=", 2)
		if len(ss) != 2 {
			continue
		}
		key, value := strings.TrimSpace(ss[0]), strings.TrimSpace(ss[1])

		switch key {
		case "ID":
			id = strings.Trim(value, `"'`)
		case "VERSION_ID":
			versionID = strings.Trim(value, `"'`)
			if versionID[0] == 'p' {
				versionID = versionID[1:]
			}
		default:
			continue
		}
		var family string
		if id == "altlinux" {
			family = aos.ALT
		}
		if family != "" && versionID != "" {
			return &analyzer.AnalysisResult{
				OS: types.OS{Family: family, Name: versionID},
			}, nil
		}
	}
	return nil, xerrors.Errorf("alpine: %w", aos.AnalyzeOSError)
}

func (a altOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}
func (a altOSAnalyzer) requiredFiles() []string {
	return []string{
		"etc/os-release",
	}
}

func (a altOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeALT
}

func (a altOSAnalyzer) Version() int {
	return altAnalyzerVersion
}
