package environment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

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

	if res == nil {
		return nil, nil
	}

	once := sync.Once{}
	// res always contains only 1 Application
	// cf. https://github.com/aquasecurity/trivy/blob/0ccdbfbb6598a52de7cda603ab22e794f710e86c/pkg/fanal/analyzer/language/analyze.go#L32
	for i, pkg := range res.Applications[0].Packages {
		// Skip packages without a version, because in this case we will not be able to get the correct file name.
		if pkg.Version != "" {
			licenses, err := findLicenseFromEnvDir(pkg)
			if err != nil {
				// Show log once per file
				once.Do(func() {
					log.WithPrefix("conda").Debug("License not found. For more information, see https://aquasecurity.github.io/trivy/latest/docs/coverage/os/conda/#licenses",
						log.String("file", input.FilePath), log.String("pkg", pkg.Name), log.Err(err))
				})
			}
			pkg.Licenses = licenses
		}
		pkg.FilePath = "" // remove `prefix` from FilePath
		res.Applications[0].Packages[i] = pkg

	}

	return res, nil
}

func findLicenseFromEnvDir(pkg types.Package) ([]string, error) {
	if pkg.FilePath == "" {
		return nil, xerrors.Errorf("`prefix` field doesn't exist")
	}
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
		matched, err := doublestar.Match(pattern, entry.Name())
		if err != nil {
			return nil, xerrors.Errorf("incorrect packageJSON file pattern: %w", err)
		}
		if matched {
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
