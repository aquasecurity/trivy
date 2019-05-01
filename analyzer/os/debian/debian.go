package debian

import (
	"bufio"
	"bytes"
	"errors"
	"regexp"
	"strings"

	"github.com/knqyf263/fanal/analyzer/os"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&debianOSAnalyzer{})
}

type debianOSAnalyzer struct{}

func (a debianOSAnalyzer) Analyze(fileMap extractor.FileMap) (analyzer.OS, error) {
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()

			// Ubuntu also exist debian_version, but format is not number
			re := regexp.MustCompile(`(\d+).(\d+)`)
			if re.MatchString(strings.TrimSpace(line)) {
				return analyzer.OS{Family: os.Debian, Name: line}, nil
			}
		}
	}
	return analyzer.OS{}, errors.New("debian: Not match")
}

func (a debianOSAnalyzer) RequiredFiles() []string {
	return []string{"etc/debian_version"}
}
