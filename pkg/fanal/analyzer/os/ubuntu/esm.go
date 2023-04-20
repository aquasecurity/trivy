package ubuntu

import (
	"context"
	"os"

	"encoding/json"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

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
	st := status{}
	err := json.NewDecoder(input.Content).Decode(&st)
	if err != nil {
		return nil, xerrors.Errorf("ubuntu ESM analyze error: %w", err)
	}
	if esmEnabled(st) {
		return &analyzer.AnalysisResult{
			OS: types.OS{
				Family:   aos.Ubuntu,
				Extended: true,
			},
		}, nil
	}
	// if ESM is disabled - return nil to reduce the amount of logic in the OS.Merge function
	return nil, nil
}

func (a ubuntuESMAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(ESMRequiredFiles, filePath)
}

func (a ubuntuESMAnalyzer) Type() analyzer.Type {
	return analyzer.TypeUbuntuESM
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

func esmEnabled(st status) bool {
	for _, s := range st.Services { // Find ESM Service
		if s.Name == esmServiceName && s.Status == esmStatusEnabled {
			return true
		}
	}
	return false
}
