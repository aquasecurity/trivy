package alpine

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&alpineOSAnalyzer{})
}

type alpineOSAnalyzer struct{}

func (a alpineOSAnalyzer) Analyze(filesMap extractor.FilesMap) (analyzer.OS, error) {
	for _, filename := range a.RequiredFiles() {
		file, ok := filesMap[filename]
		if !ok {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			// TODO
			line := scanner.Text()
			fmt.Println(line)
		}
	}
	return analyzer.OS{}, errors.New("alpine: Not match")
}

func (a alpineOSAnalyzer) RequiredFiles() []string {
	return []string{"etc/alpine-release"}
}
