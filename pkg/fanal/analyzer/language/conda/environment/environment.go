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
	"github.com/aquasecurity/trivy/pkg/version/doc"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&environmentAnalyzer{})
}

const version = 2

type parser struct{}

func (*parser) Parse(r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	p := environment.NewParser()
	pkgs, err := p.Parse(r)
	if err != nil {
		return nil, nil, err
	}

	once := sync.Once{}
	for i, pkg := range pkgs.Packages {
		// Skip packages without a version, because in this case we will not be able to get the correct file name.
		if pkg.Version != "" {
			licenses, err := findLicenseFromEnvDir(pkg, pkgs.Prefix)
			if err != nil {
				// Show log once per file
				once.Do(func() {
					// e.g. https://aquasecurity.github.io/trivy/latest/docs/coverage/os/conda/#license_1
					log.WithPrefix("conda").Debug(fmt.Sprintf("License not found. See %s for details.", doc.URL("docs/coverage/os/conda/", "license_1")),
						log.String("pkg", pkg.Name), log.Err(err))
				})
			}
			pkg.Licenses = licenses
		}
		pkgs.Packages[i] = pkg
	}

	return pkgs.Packages, nil, nil
}

type environmentAnalyzer struct{}

func (a environmentAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.CondaEnv, input.FilePath, input.Content, &parser{})
	if err != nil {
		return nil, xerrors.Errorf("unable to parse environment.yaml: %w", err)
	}

	if res == nil {
		return nil, nil
	}
	return res, nil
}

func findLicenseFromEnvDir(pkg types.Package, prefix string) ([]string, error) {
	if prefix == "" {
		return nil, xerrors.Errorf("`prefix` field doesn't exist")
	}
	condaMetaDir := filepath.Join(prefix, "conda-meta")
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
