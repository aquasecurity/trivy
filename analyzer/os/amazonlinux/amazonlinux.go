package amazonlinux

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&amazonlinuxOSAnalyzer{})
}

type amazonlinuxOSAnalyzer struct{}

func (a amazonlinuxOSAnalyzer) Analyze(fileMap extractor.FileMap) (types.OS, error) {
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			// Only Amazon Linux Prefix
			if strings.HasPrefix(line, "Amazon Linux release 2") {
				return types.OS{
					Family: os.Amazon,
					Name:   fmt.Sprintf("%s %s", fields[3], fields[4]),
				}, nil
			} else if strings.HasPrefix(line, "Amazon Linux") {
				return types.OS{
					Family: os.Amazon,
					Name:   strings.Join(fields[2:], " "),
				}, nil
			}
		}
	}
	return types.OS{}, xerrors.Errorf("amazon linux: %w", os.AnalyzeOSError)
}

func (a amazonlinuxOSAnalyzer) RequiredFiles() []string {
	return []string{"etc/system-release"}
}
