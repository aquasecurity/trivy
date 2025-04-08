package release

import (
	"bufio"
	"context"
	"os"
	"slices"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
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

		var family types.OSType
		switch id {
		case "alpine":
			family = types.Alpine
		case "opensuse-tumbleweed":
			family = types.OpenSUSETumbleweed
		case "opensuse-leap", "opensuse": // opensuse for leap:42, opensuse-leap for leap:15
			family = types.OpenSUSELeap
		case "sles":
			family = types.SLES
		// There are various rebrands of SLE Micro, there is also one brief (and reverted rebrand)
		// for SLE Micro 6.0. which was called "SL Micro 6.0" until very short before release
		// and there is a "SLE Micro for Rancher" rebrand, which is used by SUSEs K8S based offerings.
		case "sle-micro", "sl-micro", "sle-micro-rancher":
			family = types.SLEMicro
		case "photon":
			family = types.Photon
		case "wolfi":
			family = types.Wolfi
		case "chainguard":
			family = types.Chainguard
		case "azurelinux":
			family = types.Azure
		case "mariner":
			family = types.CBLMariner
		}

		if family != "" && versionID != "" {
			return &analyzer.AnalysisResult{
				OS: types.OS{
					Family: family,
					Name:   versionID,
				},
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

// StaticPaths returns the static paths of the os-release analyzer
func (a osReleaseAnalyzer) StaticPaths() []string {
	return requiredFiles
}
