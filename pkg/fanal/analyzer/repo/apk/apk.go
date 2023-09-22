package apk

import (
	"bufio"
	"context"
	"os"
	"regexp"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	ver "github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&apkRepoAnalyzer{})
}

const version = 1
const edgeVersion = "edge"

var (
	requiredFiles  = []string{"etc/apk/repositories"}
	urlParseRegexp = regexp.MustCompile(`(https*|ftp)://[0-9A-Za-z.-]+/([A-Za-z]+)/v?([0-9A-Za-z_.-]+)/`)
)

type apkRepoAnalyzer struct{}

func (a apkRepoAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	var osFamily types.OSType
	var repoVer string
	for scanner.Scan() {
		line := scanner.Text()

		m := urlParseRegexp.FindStringSubmatch(line)
		if len(m) != 4 {
			continue
		}

		newOSFamily := types.OSType(m[2])
		newVersion := m[3]

		// Find OS Family
		if osFamily != "" && osFamily != newOSFamily {
			return nil, xerrors.Errorf("mixing different distributions in etc/apk/repositories: %s != %s", osFamily, newOSFamily)
		}
		osFamily = newOSFamily

		// Find max Release version
		switch {
		case repoVer == "":
			repoVer = newVersion
		case repoVer == edgeVersion || newVersion == edgeVersion:
			repoVer = edgeVersion
		default:
			oldVer, err := ver.Parse(repoVer)
			if err != nil {
				continue
			}
			newVer, err := ver.Parse(newVersion)
			if err != nil {
				continue
			}

			// Take the maximum version in apk repositories
			if newVer.GreaterThan(oldVer) {
				repoVer = newVersion
			}
		}
	}

	// Currently, we support only Alpine Linux in apk repositories.
	if osFamily != types.Alpine || repoVer == "" {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Repository: &types.Repository{
			Family:  osFamily,
			Release: repoVer,
		},
	}, nil
}

func (a apkRepoAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a apkRepoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApkRepo
}

func (a apkRepoAnalyzer) Version() int {
	return version
}
