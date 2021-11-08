package cloudformation

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".yaml", ".json", ".yml"}

var awsConfigurationRegex = regexp.MustCompile(`(?i)(?m)^\s*?["|]?AWSTemplateFormatVersion[:|"]?`)
var cloudFormationMatchRegex = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?m)^\s*?["|]?Resources[:|"]?`),
	regexp.MustCompile(`(?i)(?m)^\s*?["|]?Parameters[:|"]?`),
}

type ConfigAnalyzer struct {
}

func NewConfigAnalyzer() ConfigAnalyzer {
	return ConfigAnalyzer{}
}

// Analyze returns a results of CloudFormation file
func (a ConfigAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {

	if looksLikeCloudFormation(target.Content) {
		return &analyzer.AnalysisResult{
			Configs: []types.Config{
				{
					Type:     types.CloudFormation,
					FilePath: filepath.Join(target.Dir, target.FilePath),
				},
			},
		}, nil
	}
	return &analyzer.AnalysisResult{}, nil
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	for _, extension := range requiredExts {
		if filepath.Ext(filePath) == extension {
			return true
		}
	}
	return false
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCloudFormation
}

func (ConfigAnalyzer) Version() int {
	return version
}

func looksLikeCloudFormation(content []byte) bool {

	if awsConfigurationRegex.MatchString(string(content)) {
		return true
	}

	for _, regex := range cloudFormationMatchRegex {
		if !regex.MatchString(string(content)) {
			return false
		}
	}

	return true
}
