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
	// Lock file name can be anything (https://docs.conan.io/en/latest/versioning/lockfiles/introduction.html#locking-dependencies)
	// By default, we only check default filename - `conan.lock`
	fileName = "conan.lock"
)

// conanLockAnalyzer analyzes conan.lock
type conanLockAnalyzer struct{}

func (a conanLockAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := conan.NewParser()
	res, err := language.Analyze(types.ConanLock, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}
	return res, nil
}

func (a conanLockAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	return fileInfo.Name() == fileName
}

func (a conanLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeConanLock
}

func (a conanLockAnalyzer) Version() int {
	return version
}
