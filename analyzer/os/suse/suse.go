package suse

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
	analyzer.RegisterOSAnalyzer(&suseOSAnalyzer{})
}

type suseOSAnalyzer struct{}

func (a suseOSAnalyzer) Analyze(fileMap extractor.FileMap) (types.OS, error) {
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		suseName := ""
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "NAME=\"openSUSE") {
				if strings.Contains(line, "Leap") {
					suseName = os.OpenSUSELeap
				} else if strings.Contains(line, "Tumbleweed") {
					suseName = os.OpenSUSETumbleweed
				} else {
					suseName = os.OpenSUSE
				}
				continue
			}
			if strings.HasPrefix(line, "NAME=\"SLES") {
				suseName = os.SLES
				continue
			}

			if suseName != "" && strings.HasPrefix(line, "VERSION_ID=") {
				return types.OS{
					Family: suseName,
					Name:   strings.TrimSpace(line[12 : len(line)-1]),
				}, nil
			}
		}
	}
	return types.OS{}, xerrors.Errorf("suse: %w", os.AnalyzeOSError)
}

func (a suseOSAnalyzer) RequiredFiles() []string {
	return []string{
		"usr/lib/os-release",
		"etc/os-release",
	}
}
