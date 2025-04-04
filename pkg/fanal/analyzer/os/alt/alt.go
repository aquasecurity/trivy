package alt

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&altOSAnalyzer{})
}

const altAnalyzerVersion = 1

var requiredFiles = []string{"etc/os-release"}

type altOSAnalyzer struct{}

func (a altOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	var cpe string
	for scanner.Scan() {
		line := scanner.Text()
		ss := strings.SplitN(line, "=", 2)
		if len(ss) != 2 {
			continue
		}
		key, value := strings.TrimSpace(ss[0]), strings.TrimSpace(ss[1])

		switch key {
		case "ID":
			id := strings.Trim(value, `"'`)
			if !strings.Contains(id, "altlinux") {
				return nil, nil
			}
			continue
		case "CPE_NAME":
			cpe = strings.Trim(value, `"'`)
		default:
			continue
		}
		return &analyzer.AnalysisResult{
			OS: types.OS{Family: types.ALT, Name: cpe},
		}, nil
	}
	return nil, xerrors.Errorf("alt: %w", fos.AnalyzeOSError)
}

func (a altOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a altOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeALT
}

func (a altOSAnalyzer) Version() int {
	return altAnalyzerVersion
}
