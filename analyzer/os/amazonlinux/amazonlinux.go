package amazonlinux

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/utils"

	"github.com/aquasecurity/fanal/types"

	aos "github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&amazonlinuxOSAnalyzer{})
}

var requiredFiles = []string{"etc/system-release"}

type amazonlinuxOSAnalyzer struct{}

func (a amazonlinuxOSAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	foundOS, err := a.parseRelease(content)
	if err != nil {
		return analyzer.AnalyzeReturn{}, err
	}
	return analyzer.AnalyzeReturn{
		OS: foundOS,
	}, nil
}

func (a amazonlinuxOSAnalyzer) parseRelease(content []byte) (types.OS, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// Only Amazon Linux Prefix
		if strings.HasPrefix(line, "Amazon Linux release 2") {
			if len(fields) < 5 {
				continue
			}
			return types.OS{
				Family: aos.Amazon,
				Name:   fmt.Sprintf("%s %s", fields[3], fields[4]),
			}, nil
		} else if strings.HasPrefix(line, "Amazon Linux") {
			return types.OS{
				Family: aos.Amazon,
				Name:   strings.Join(fields[2:], " "),
			}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("amazon: %w", aos.AnalyzeOSError)
}

func (a amazonlinuxOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a amazonlinuxOSAnalyzer) Name() string {
	return aos.Amazon
}
