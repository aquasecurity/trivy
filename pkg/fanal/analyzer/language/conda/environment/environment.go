package environment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/environment"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/meta"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterAnalyzer(&environmentAnalyzer{})
}

const version = 2

type environmentAnalyzer struct{}

func (a environmentAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.CondaEnv, input.FilePath, input.Content, environment.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse environment.yaml: %w", err)
	}

	if res != nil && len(res.Applications) > 0 {
		// For `environment.yaml` Applications always contains only 1 Application
		for i, pkg := range res.Applications[0].Packages {
			licenses, err := findLicenseFromEnvDir(pkg)
			if err != nil {
				log.WithPrefix("conda").Debug("License didn't found", log.String("pkgName", pkg.Name), log.String("version", pkg.Version), log.Err(err))
			}
			pkg.Licenses = licenses
			pkg.FilePath = "" // remove path to env dir
			res.Applications[0].Packages[i] = pkg
		}

	}

	return res, nil
}

func findLicenseFromEnvDir(pkg types.Package) ([]string, error) {
	condaMetaDir := filepath.Join(pkg.FilePath, "conda-meta")
	entries, err := os.ReadDir(condaMetaDir)
	if err != nil {
		return nil, xerrors.Errorf("unable to read conda-meta dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		pattern := fmt.Sprintf("%s-%s-*.json", pkg.Name, pkg.Version)
		if matched, _ := doublestar.Match(pattern, entry.Name()); matched {
			file, err := os.Open(filepath.Join(condaMetaDir, entry.Name()))
			if err != nil {
				return nil, xerrors.Errorf("unable to open packageJSON file: %w", err)
			}
			packageJson, _, err := meta.NewParser().Parse(file)
			if err != nil {
				return nil, xerrors.Errorf("unable to parse packageJSON file: %w", err)
			}
			// packageJson always contain only 1 element
			// cf. https://github.com/aquasecurity/trivy/blob/c3192f061d7e84eaf38df8df7c879dc00b4ca137/pkg/dependency/parser/conda/meta/parse.go#L39-L45
			return packageJson[0].Licenses, nil
		}
	}
	return nil, xerrors.Errorf("meta file didn't find")
}

func (a environmentAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.CondaEnvYml || filepath.Base(filePath) == types.CondaEnvYaml
}

func (a environmentAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCondaEnv
}

func (a environmentAnalyzer) Version() int {
	return version
}
