package photon

import (
	"bufio"
	"bytes"
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

var requiredFiles = []string{
	"usr/lib/os-release",
	"etc/os-release",
}

type photonOSAnalyzer struct{}

func (a photonOSAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	photonName := ""
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=\"VMware Photon") {
			photonName = aos.Photon
			continue
		}

		if photonName != "" && strings.HasPrefix(line, "VERSION_ID=") {
			return analyzer.AnalyzeReturn{
				OS: types.OS{
					Family: photonName,
					Name:   strings.TrimSpace(line[11:]),
				},
			}, nil
		}
	}
	return analyzer.AnalyzeReturn{}, xerrors.Errorf("photon: %w", aos.AnalyzeOSError)
}

func (a photonOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a photonOSAnalyzer) Name() string {
	return aos.Photon
}
