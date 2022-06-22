package ubuntu

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"

	"golang.org/x/xerrors"
	"k8s.io/utils/strings/slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&ubuntuOSAnalyzer{})
}

const (
	version            = 1
	ubuntuConfFilePath = "etc/lsb-release"
	esmConfFilePath    = "var/lib/ubuntu-advantage/status.json"
	esmServiceName     = "esm-infra"
	esmStatusEnabled   = "enabled"
	esmVersionSuffix   = "ESM"
)

var requiredFiles = []string{
	ubuntuConfFilePath,
	esmConfFilePath,
}

type ubuntuOSAnalyzer struct{}

func (a ubuntuOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	isUbuntu := false
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "DISTRIB_ID=Ubuntu" {
			isUbuntu = true
			continue
		}

		if isUbuntu && strings.HasPrefix(line, "DISTRIB_RELEASE=") {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Ubuntu,
					Name:   strings.TrimSpace(line[16:]),
				},
			}, nil
		}

		if input.FilePath == esmConfFilePath { // Check esm config file
			if esmEnabled(line) {
				return &analyzer.AnalysisResult{
					OS: &types.OS{
						Family:   aos.Ubuntu,
						Extended: esmVersionSuffix,
					},
				}, nil
			} else {
				return nil, nil
			}
		}
	}
	return nil, xerrors.Errorf("ubuntu: %w", aos.AnalyzeOSError)
}

func (a ubuntuOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a ubuntuOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeUbuntu
}

func (a ubuntuOSAnalyzer) Version() int {
	return version
}

// structs to parse ESM status
type status struct {
	Services []service `json:"services"`
}

type service struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func esmEnabled(config string) bool {
	st := status{}

	err := json.Unmarshal([]byte(config), &st)
	if err != nil {
		return false
	}

	for _, s := range st.Services { // Find ESM Service
		if s.Name == esmServiceName && s.Status == esmStatusEnabled {
			return true
		}
	}
	return false
}
