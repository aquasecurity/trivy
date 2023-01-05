package pub

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/dart/pub"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pubSpecLockAnalyzer{})
}

const (
	version = 1
)

// pubSpecLockAnalyzer analyzes pubspec.lock
type pubSpecLockAnalyzer struct{}

func (a pubSpecLockAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := pub.NewParser()
	res, err := language.Analyze(types.Pub, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}
	return res, nil
}

func (a pubSpecLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.PubSpecLock
}

func (a pubSpecLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypePubSpecLock
}

func (a pubSpecLockAnalyzer) Version() int {
	return version
}
