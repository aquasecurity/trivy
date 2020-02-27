package alpine

import (
	"bufio"
	"bytes"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&alpineOSAnalyzer{})
}

type alpineOSAnalyzer struct{}

func (a alpineOSAnalyzer) Analyze(fileMap extractor.FileMap) (types.OS, error) {
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			return types.OS{Family: os.Alpine, Name: line}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("alpine: %w", os.AnalyzeOSError)
}

func (a alpineOSAnalyzer) RequiredFiles() []string {
	return []string{"etc/alpine-release"}
}
