package conan

import (
	"context"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/c/conan"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&conanLockAnalyzer{})
}

const (
	version = 1
)

// conanLockAnalyzer analyzes conan.lock
type conanLockAnalyzer struct{}

func (a conanLockAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := conan.NewParser()
	res, err := language.Analyze(types.Conan, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}
	return res, nil
}

func (a conanLockAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	// Lock file name can be anything
	// cf. https://docs.conan.io/en/latest/versioning/lockfiles/introduction.html#locking-dependencies
	// By default, we only check the default filename - `conan.lock`.
	return fileInfo.Name() == types.ConanLock
}

func (a conanLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeConanLock
}

func (a conanLockAnalyzer) Version() int {
	return version
}
