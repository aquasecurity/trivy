package release

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&osReleaseAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"etc/os-release",
	"usr/lib/os-release",
}

type osReleaseAnalyzer struct{}

func (a osReleaseAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
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
		default:
			continue
		}

		var family string
		switch id {
		case "alpine":
			family = aos.Alpine
		case "opensuse-tumbleweed":
			family = aos.OpenSUSETumbleweed
		case "opensuse-leap", "opensuse": // opensuse for leap:42, opensuse-leap for leap:15
			family = aos.OpenSUSELeap
		case "sles":
			family = aos.SLES
		case "photon":
			family = aos.Photon
		case "wolfi":
			family = aos.Wolfi
		}

		if family != "" && versionID != "" {
			return &analyzer.AnalysisResult{
				OS: types.OS{Family: family, Name: versionID},
			}, nil
		}
	}

	return nil, nil
}

func (a osReleaseAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a osReleaseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeOSRelease
}

func (a osReleaseAnalyzer) Version() int {
	return version
}
