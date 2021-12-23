package photon

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/utils"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&photonOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"usr/lib/os-release",
	"etc/os-release",
}

type photonOSAnalyzer struct{}

func (a photonOSAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	photonName := ""
	scanner := bufio.NewScanner(target.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=\"VMware Photon") {
			photonName = aos.Photon
			continue
		}

		if photonName != "" && strings.HasPrefix(line, "VERSION_ID=") {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: photonName,
					Name:   strings.TrimSpace(line[11:]),
				},
			}, nil
		}
	}
	return nil, xerrors.Errorf("photon: %w", aos.AnalyzeOSError)
}

func (a photonOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a photonOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypePhoton
}

func (a photonOSAnalyzer) Version() int {
	return version
}
