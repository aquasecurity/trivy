package ubuntu

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
	analyzer.RegisterOSAnalyzer(&ubuntuOSAnalyzer{})
}

type ubuntuOSAnalyzer struct{}

func (a ubuntuOSAnalyzer) Analyze(fileMap extractor.FileMap) (analyzer.OS, error) {
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		isUbuntu := false
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "DISTRIB_ID=Ubuntu" {
				isUbuntu = true
				continue
			}

			if isUbuntu && strings.HasPrefix(line, "DISTRIB_RELEASE=") {
				return analyzer.OS{
					Family: os.Ubuntu,
					Name:   strings.TrimSpace(line[16:]),
				}, nil
			}
		}
	}
	return analyzer.OS{}, errors.New("ubuntu: Not match")
}

func (a ubuntuOSAnalyzer) RequiredFiles() []string {
	return []string{"etc/lsb-release"}
}
