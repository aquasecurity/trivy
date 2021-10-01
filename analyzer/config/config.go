package config

import (
	"regexp"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/docker"
	"github.com/aquasecurity/fanal/analyzer/config/hcl"
	"github.com/aquasecurity/fanal/analyzer/config/json"
	"github.com/aquasecurity/fanal/analyzer/config/terraform"
	"github.com/aquasecurity/fanal/analyzer/config/toml"
	"github.com/aquasecurity/fanal/analyzer/config/yaml"
	"github.com/aquasecurity/fanal/types"
)

const separator = ":"

type ScannerOption struct {
	Trace        bool
	Namespaces   []string
	FilePatterns []string
	PolicyPaths  []string
	DataPaths    []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.FilePatterns)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

func RegisterConfigAnalyzers(filePatterns []string) error {
	var dockerRegexp, hclRegexp, jsonRegexp, tomlRegexp, yamlRegexp *regexp.Regexp
	for _, p := range filePatterns {
		// e.g. "dockerfile:my_dockerfile_*"
		s := strings.SplitN(p, separator, 2)
		if len(s) != 2 {
			return xerrors.Errorf("invalid file pattern (%s)", p)
		}
		fileType, pattern := s[0], s[1]
		r, err := regexp.Compile(pattern)
		if err != nil {
			return xerrors.Errorf("invalid file regexp (%s): %w", p, err)
		}

		switch fileType {
		case types.Dockerfile:
			dockerRegexp = r
		case types.HCL:
			hclRegexp = r
		case types.JSON:
			jsonRegexp = r
		case types.TOML:
			tomlRegexp = r
		case types.YAML:
			yamlRegexp = r
		default:
			return xerrors.Errorf("unknown file type: %s, pattern: %s", fileType, pattern)
		}
	}

	analyzer.RegisterAnalyzer(docker.NewConfigAnalyzer(dockerRegexp))
	analyzer.RegisterAnalyzer(hcl.NewConfigAnalyzer(hclRegexp))
	analyzer.RegisterAnalyzer(json.NewConfigAnalyzer(jsonRegexp))
	analyzer.RegisterAnalyzer(terraform.NewConfigAnalyzer())
	analyzer.RegisterAnalyzer(toml.NewConfigAnalyzer(tomlRegexp))
	analyzer.RegisterAnalyzer(yaml.NewConfigAnalyzer(yamlRegexp))

	return nil
}
