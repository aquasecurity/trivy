package photon

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&photonOSAnalyzer{})
}

type photonOSAnalyzer struct{}

func (a photonOSAnalyzer) Analyze(fileMap extractor.FileMap) (types.OS, error) {
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		photonName := ""
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "NAME=\"VMware Photon") {
				photonName = os.Photon
				continue
			}

			if photonName != "" && strings.HasPrefix(line, "VERSION_ID=") {
				return types.OS{
					Family: photonName,
					Name:   strings.TrimSpace(line[11:]),
				}, nil
			}
		}
	}
	return types.OS{}, xerrors.Errorf("photon: %w", os.AnalyzeOSError)
}

func (a photonOSAnalyzer) RequiredFiles() []string {
	return []string{
		"usr/lib/os-release",
		"etc/os-release",
	}
}
