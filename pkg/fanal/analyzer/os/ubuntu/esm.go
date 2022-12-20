package ubuntu

import (
	"bufio"
	"context"
	"encoding/json"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&ubuntuESMAnalyzer{})
}

const (
	ESMAnalyzerVersion = 1
	esmConfFilePath    = "var/lib/ubuntu-advantage/status.json"
	esmServiceName     = "esm-infra"
	esmStatusEnabled   = "enabled"
)

var ESMRequiredFiles = []string{
	esmConfFilePath,
}

type ubuntuESMAnalyzer struct{}

func (a ubuntuESMAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		enable, err := esmEnabled(line)
		if err != nil {
			return nil, xerrors.Errorf("ubuntu ESM analyze error: %w", err)
		}
		if enable {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family:   aos.Ubuntu,
					Extended: true,
				},
			}, nil
		} else { // if ESM is disabled - return nil to reduce the amount of logic in the MergeOsVersion function
			return nil, nil
		}
	}
	return nil, xerrors.Errorf("ubuntu ESM: %w", aos.AnalyzeOSError)
}

func (a ubuntuESMAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(ESMRequiredFiles, filePath)
}

func (a ubuntuESMAnalyzer) Type() analyzer.Type {
	return analyzer.TypeUbuntu
}

func (a ubuntuESMAnalyzer) Version() int {
	return ESMAnalyzerVersion
}

// structs to parse ESM status
type status struct {
	Services []service `json:"services"`
}

type service struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func esmEnabled(line string) (bool, error) {
	st := status{}

	err := json.Unmarshal([]byte(line), &st)
	if err != nil {
		return false, err
	}

	for _, s := range st.Services { // Find ESM Service
		if s.Name == esmServiceName && s.Status == esmStatusEnabled {
			return true, nil
		}
	}
	return false, nil
}
