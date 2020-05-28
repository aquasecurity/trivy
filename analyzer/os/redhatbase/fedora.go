package redhatbase

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&fedoraOSAnalyzer{})
}

type fedoraOSAnalyzer struct{}

func (a fedoraOSAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return analyzer.AnalyzeReturn{}, xerrors.New("cent: Invalid fedora-release")
		}

		switch strings.ToLower(result[1]) {
		case "fedora", "fedora linux":
			return analyzer.AnalyzeReturn{
				OS: types.OS{Family: aos.Fedora, Name: result[2]},
			}, nil
		}
	}
	return analyzer.AnalyzeReturn{}, xerrors.Errorf("fedora: %w", aos.AnalyzeOSError)
}

func (a fedoraOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a fedoraOSAnalyzer) requiredFiles() []string {
	return []string{
		"etc/fedora-release",
		"usr/lib/fedora-release",
	}
}

func (a fedoraOSAnalyzer) Name() string {
	return aos.Fedora
}
