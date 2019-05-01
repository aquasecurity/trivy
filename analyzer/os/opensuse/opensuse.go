package opensuse

import (
	"bufio"
	"bytes"
	"errors"
	"strings"

	"github.com/knqyf263/fanal/analyzer/os"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&opensuseOSAnalyzer{})
}

type opensuseOSAnalyzer struct{}

// TODO : need investigation
func (a opensuseOSAnalyzer) Analyze(fileMap extractor.FileMap) (analyzer.OS, error) {
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

			if suseName != "" && strings.HasPrefix(line, "VERSION_ID=") {
				return analyzer.OS{
					Family: suseName,
					Name:   strings.TrimSpace(line[12 : len(line)-1]),
				}, nil
			}
		}
	}
	return analyzer.OS{}, errors.New("opensuse: Not match")
}

func (a opensuseOSAnalyzer) RequiredFiles() []string {
	return []string{
		"usr/lib/os-release",
		"etc/os-release",
	}
}
