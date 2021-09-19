package redhatbase

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/utils"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
)

const redhatAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&redhatOSAnalyzer{})
}

var redhatRe = regexp.MustCompile(`(.*) release (\d[\d\.]*)`)

type redhatOSAnalyzer struct{}

func (a redhatOSAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	foundOS, err := a.parseRelease(target.Content)
	if err != nil {
		return nil, err
	}
	return &analyzer.AnalysisResult{
		OS: &foundOS,
	}, nil

}

func (a redhatOSAnalyzer) parseRelease(content []byte) (types.OS, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return types.OS{}, xerrors.New("redhat: invalid redhat-release")
		}

		switch strings.ToLower(result[1]) {
		case "centos", "centos linux":
			return types.OS{Family: aos.CentOS, Name: result[2]}, nil
		case "rocky", "rocky linux":
			return types.OS{Family: aos.Rocky, Name: result[2]}, nil
		case "alma", "almalinux", "alma linux":
			return types.OS{Family: aos.Alma, Name: result[2]}, nil
		case "oracle", "oracle linux", "oracle linux server":
			return types.OS{Family: aos.Oracle, Name: result[2]}, nil
		case "fedora", "fedora linux":
			return types.OS{Family: aos.Fedora, Name: result[2]}, nil
		default:
			return types.OS{Family: aos.RedHat, Name: result[2]}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("redhatbase: %w", aos.AnalyzeOSError)
}

func (a redhatOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a redhatOSAnalyzer) requiredFiles() []string {
	return []string{"etc/redhat-release"}
}

func (a redhatOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRedHatBase
}

func (a redhatOSAnalyzer) Version() int {
	return redhatAnalyzerVersion
}
