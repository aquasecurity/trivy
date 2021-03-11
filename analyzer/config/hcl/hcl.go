package hcl

import (
	"os"
	"path/filepath"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/open-policy-agent/conftest/parser/hcl1"
	"github.com/open-policy-agent/conftest/parser/hcl2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&hclConfigAnalyzer{
		hcl1Parser: &hcl1.Parser{},
		hcl2Parser: &hcl2.Parser{},
	})
}

const version = 1

var requiredExts = []string{".hcl", ".hcl1", ".hcl2", ".tf"}

type hclConfigAnalyzer struct {
	hcl1Parser *hcl1.Parser
	hcl2Parser *hcl2.Parser
}

// Analyze analyzes HCL-based config files, defaulting to HCL2.0 spec
// it returns error only if content does not comply to both HCL2.0 and HCL1.0 spec
func (a hclConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var errs error
	var parsed interface{}

	if err := a.hcl2Parser.Unmarshal(target.Content, &parsed); err != nil {
		errs = multierror.Append(errs, xerrors.Errorf("unable to parse HCL2 (%s): %w", target.FilePath, err))
	} else {
		return &analyzer.AnalysisResult{
			Configs: []types.Config{{
				Type:     config.HCL2,
				FilePath: target.FilePath,
				Content:  parsed,
			}},
		}, nil
	}

	if err := a.hcl1Parser.Unmarshal(target.Content, &parsed); err != nil {
		errs = multierror.Append(errs, xerrors.Errorf("unable to parse HCL1 (%s): %w", target.FilePath, err))
	} else {
		return &analyzer.AnalysisResult{
			Configs: []types.Config{{
				Type:     config.HCL1,
				FilePath: target.FilePath,
				Content:  parsed,
			}},
		}, nil
	}

	return nil, errs
}

func (a hclConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (a hclConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHCL
}

func (a hclConfigAnalyzer) Version() int {
	return version
}
