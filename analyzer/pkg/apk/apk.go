package apk

import (
	"bufio"
	"bytes"
	"fmt"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
	"github.com/pkg/errors"
)

func init() {
	analyzer.RegisterPkgAnalyzer(&alpinePkgAnalyzer{})
}

type alpinePkgAnalyzer struct{}

func (a alpinePkgAnalyzer) Analyze(filesMap extractor.FilesMap) ([]analyzer.Package, error) {
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
	return []analyzer.Package{}, errors.New("alpine: Not match")
}

func (a alpinePkgAnalyzer) RequiredFiles() []string {
	return []string{"lib/apk/db/installed"}
}
