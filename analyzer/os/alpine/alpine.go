package alpine

import (
	"bufio"
	"bytes"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&alpineOSAnalyzer{})
}

var requiredFiles = []string{"etc/alpine-release"}

type alpineOSAnalyzer struct{}

func (a alpineOSAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()
		return analyzer.AnalyzeReturn{
			OS: types.OS{Family: aos.Alpine, Name: line},
		}, nil
	}
	return analyzer.AnalyzeReturn{}, xerrors.Errorf("alpine: %w", aos.AnalyzeOSError)
}

func (a alpineOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a alpineOSAnalyzer) Name() string {
	return aos.Alpine
}
