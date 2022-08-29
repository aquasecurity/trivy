package config

import (
	"regexp"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/helm"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/dockerfile"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/json"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/terraform"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/yaml"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const separator = ":"

type ScannerOption struct {
	Trace                   bool
	RegoOnly                bool
	Namespaces              []string
	FilePatterns            []string
	PolicyPaths             []string
	DataPaths               []string
	DisableEmbeddedPolicies bool

	HelmValues       []string
	HelmValueFiles   []string
	HelmFileValues   []string
	HelmStringValues []string
	TerraformTFVars  []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.FilePatterns)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

func RegisterConfigAnalyzers(filePatterns []string) error {
	var dockerRegexp, jsonRegexp, yamlRegexp, helmRegexp *regexp.Regexp
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
		case types.JSON:
			jsonRegexp = r
		case types.YAML:
			yamlRegexp = r
		case types.Helm:
			helmRegexp = r
		default:
			return xerrors.Errorf("unknown file type: %s, pattern: %s", fileType, pattern)
		}
	}

	analyzer.RegisterAnalyzer(dockerfile.NewConfigAnalyzer(dockerRegexp))
	analyzer.RegisterAnalyzer(terraform.NewConfigAnalyzer())
	analyzer.RegisterAnalyzer(json.NewConfigAnalyzer(jsonRegexp))
	analyzer.RegisterAnalyzer(yaml.NewConfigAnalyzer(yamlRegexp))
	analyzer.RegisterAnalyzer(helm.NewConfigAnalyzer(helmRegexp))

	return nil
}
