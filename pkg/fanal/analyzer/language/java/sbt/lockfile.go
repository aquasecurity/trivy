package sbt

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/sbt/lockfile"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&sbtDependencyLockAnalyzer{})
}

const (
	version      = 1
	requiredFile = "build.sbt.lock"
)

// sbtDependencyLockAnalyzer analyzes '*.sbt.lock'
type sbtDependencyLockAnalyzer struct{}

func (a sbtDependencyLockAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	filePath := filepath.Join(input.Dir, input.FilePath)
	parser := lockfile.NewParser()

	res, err := language.Analyze(types.Sbt, filePath, input.Content, parser)

	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", filePath, err)
	}

	return res, nil
}

func (a sbtDependencyLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return requiredFile == filepath.Base(filePath)
}

func (a sbtDependencyLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeSbtLock
}

func (a sbtDependencyLockAnalyzer) Version() int {
	return version
}
