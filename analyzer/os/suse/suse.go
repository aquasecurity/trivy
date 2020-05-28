package suse

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&suseOSAnalyzer{})
}

var requiredFiles = []string{
	"usr/lib/os-release",
	"etc/os-release",
}

type suseOSAnalyzer struct{}

func (a suseOSAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	suseName := ""
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=\"openSUSE") {
			if strings.Contains(line, "Leap") {
				suseName = aos.OpenSUSELeap
			} else if strings.Contains(line, "Tumbleweed") {
				suseName = aos.OpenSUSETumbleweed
			} else {
				suseName = aos.OpenSUSE
			}
			continue
		}
		if strings.HasPrefix(line, "NAME=\"SLES") {
			suseName = aos.SLES
			continue
		}

		if suseName != "" && strings.HasPrefix(line, "VERSION_ID=") {
			return analyzer.AnalyzeReturn{
				OS: types.OS{
					Family: suseName,
					Name:   strings.TrimSpace(line[12 : len(line)-1]),
				},
			}, nil
		}
	}
	return analyzer.AnalyzeReturn{}, xerrors.Errorf("suse: %w", aos.AnalyzeOSError)
}

func (a suseOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a suseOSAnalyzer) Name() string {
	return "suse"
}
