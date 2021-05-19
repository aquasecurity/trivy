package hcl

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/hashicorp/go-multierror"
	"github.com/open-policy-agent/conftest/parser/hcl1"
	"github.com/open-policy-agent/conftest/parser/hcl2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".hcl", ".hcl1", ".hcl2", ".tf"}

type ConfigAnalyzer struct {
	hcl1Parser  *hcl1.Parser
	hcl2Parser  *hcl2.Parser
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		hcl1Parser:  &hcl1.Parser{},
		hcl2Parser:  &hcl2.Parser{},
		filePattern: filePattern,
	}
}

// Analyze analyzes HCL-based config files, defaulting to HCL2.0 spec
// it returns error only if content does not comply to both HCL2.0 and HCL1.0 spec
func (a ConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parsed, err := a.analyze(target)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse HCL (%a): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.HCL,
				FilePath: target.FilePath,
				Content:  parsed,
			},
		},
	}, nil
}

func (a ConfigAnalyzer) analyze(target analyzer.AnalysisTarget) (interface{}, error) {
	var errs error
	var parsed interface{}

	if err := a.hcl2Parser.Unmarshal(target.Content, &parsed); err != nil {
		errs = multierror.Append(errs, xerrors.Errorf("unable to parse HCL2 (%a): %w", target.FilePath, err))
	} else {
		return parsed, nil
	}

	if err := a.hcl1Parser.Unmarshal(target.Content, &parsed); err != nil {
		errs = multierror.Append(errs, xerrors.Errorf("unable to parse HCL1 (%a): %w", target.FilePath, err))
	} else {
		return parsed, nil
	}

	return nil, errs
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHCL
}

func (ConfigAnalyzer) Version() int {
	return version
}
