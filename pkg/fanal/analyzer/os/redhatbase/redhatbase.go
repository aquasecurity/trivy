package redhatbase

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

const redhatAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&redhatOSAnalyzer{})
}

var redhatRe = regexp.MustCompile(`(.*) release (\d[\d\.]*)`)

type redhatOSAnalyzer struct{}

func (a redhatOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	foundOS, err := a.parseRelease(input.Content)
	if err != nil {
		return nil, err
	}
	return &analyzer.AnalysisResult{
		OS: foundOS,
	}, nil

}

func (a redhatOSAnalyzer) parseRelease(r io.Reader) (types.OS, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return types.OS{}, xerrors.New("redhat: invalid redhat-release")
		}

		switch strings.ToLower(result[1]) {
		case "centos", "centos linux":
			return types.OS{
				Family: types.CentOS,
				Name:   result[2],
			}, nil
		case "rocky", "rocky linux":
			return types.OS{
				Family: types.Rocky,
				Name:   result[2],
			}, nil
		case "alma", "almalinux", "alma linux":
			return types.OS{
				Family: types.Alma,
				Name:   result[2],
			}, nil
		case "oracle", "oracle linux", "oracle linux server":
			return types.OS{
				Family: types.Oracle,
				Name:   result[2],
			}, nil
		case "fedora", "fedora linux":
			return types.OS{
				Family: types.Fedora,
				Name:   result[2],
			}, nil
		case "red hat enterprise linux coreos":
			// https://access.redhat.com/articles/6907891

			var major, minor, rel int

			split := strings.SplitN(result[2], ".", 4)
			major, _ = strconv.Atoi(split[0])
			if len(split) > 1 {
				minor, _ = strconv.Atoi(split[1])
			}
			if len(split) > 2 {
				rel, _ = strconv.Atoi(split[2])
			}

			coreosVersion, err := semver.Parse(fmt.Sprintf("%d.%d.%d", major, minor, rel))
			if err == nil {
				var rhelVersion string
				if coreos4_16, _ := semver.Parse("4.16.0"); coreosVersion.GreaterThanOrEqual(coreos4_16) {
					rhelVersion = "9.4"
				} else if coreos4_13, _ := semver.Parse("4.13.0"); coreosVersion.GreaterThanOrEqual(coreos4_13) {
					rhelVersion = "9.2"
				} else if coreos4_11, _ := semver.Parse("4.11.0"); coreosVersion.GreaterThanOrEqual(coreos4_11) {
					rhelVersion = "8.6"
				} else if coreos4_7_24, _ := semver.Parse("4.7.24"); coreosVersion.GreaterThanOrEqual(coreos4_7_24) {
					rhelVersion = "8.4"
				} else if coreos4_7_0, _ := semver.Parse("4.7.0"); coreosVersion.GreaterThanOrEqual(coreos4_7_0) {
					rhelVersion = "8.3"
				} else {
					rhelVersion = "8.2"
				}

				return types.OS{
					Family: types.RedHat,
					Name:   rhelVersion,
				}, nil
			}

			fallthrough
		default:
			return types.OS{
				Family: types.RedHat,
				Name:   result[2],
			}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("redhatbase: %w", fos.AnalyzeOSError)
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
