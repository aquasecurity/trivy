package mariner

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&marinerOSAnalyzer{})
}

const (
	version      = 1
	requiredFile = "etc/mariner-release"
)

type marinerOSAnalyzer struct{}

func (a marinerOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	foundOS, err := a.parseRelease(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("release parse error: %w", err)
	}
	return &analyzer.AnalysisResult{
		OS: foundOS,
	}, nil
}

func (a marinerOSAnalyzer) parseRelease(r io.Reader) (types.OS, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if strings.ToLower(fields[0]) == "cbl-mariner" {
			return types.OS{
				Family: types.CBLMariner,
				Name:   fields[1],
			}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("cbl-mariner: %w", fos.AnalyzeOSError)
}

func (a marinerOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.ToSlash(filePath) == requiredFile
}

func (a marinerOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCBLMariner
}

func (a marinerOSAnalyzer) Version() int {
	return version
}
