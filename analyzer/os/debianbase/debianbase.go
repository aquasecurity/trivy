package debianbase

import (
	"bufio"
	"bytes"
	"strings"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer/os"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&debianbaseOSAnalyzer{})
}

type debianbaseOSAnalyzer struct{}

func (a debianbaseOSAnalyzer) Analyze(fileMap extractor.FileMap) (analyzer.OS, error) {
	if file, ok := fileMap["etc/lsb-release"]; ok {
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

	if file, ok := fileMap["etc/debian_version"]; ok {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			return analyzer.OS{Family: os.Debian, Name: line}, nil
		}
	}
	return analyzer.OS{}, xerrors.Errorf("debianbase: %w", os.AnalyzeOSError)
}

func (a debianbaseOSAnalyzer) RequiredFiles() []string {
	return []string{
		"etc/lsb-release",
		"etc/debian_version",
	}
}
