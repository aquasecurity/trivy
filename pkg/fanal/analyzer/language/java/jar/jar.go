package jar

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/java_db"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterAnalyzer(&javaLibraryAnalyzer{})
}

const (
	version = 1
)

var requiredExtensions = []string{".jar", ".war", ".ear", ".par"}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct{}

func (a javaLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	dbCacheDir, err := java_db.UpdateJavaDB()
	if err != nil {
		// if dbCacheDir == "" => db.Searcher will not be init
		log.Logger.Warnf("disable search jars with trivy-java-db. Update error: %s", err)
	}
	p := jar.NewParser(jar.WithSize(input.Info.Size()), jar.WithFilePath(input.FilePath), jar.WithOffline(input.Options.Offline), jar.WithDBDir(dbCacheDir))
	libs, deps, err := p.Parse(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("jar/war/ear/par parse error: %w", err)
	}

	return language.ToAnalysisResult(types.Jar, input.FilePath, input.FilePath, libs, deps), nil
}

func (a javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a javaLibraryAnalyzer) Version() int {
	return version
}
