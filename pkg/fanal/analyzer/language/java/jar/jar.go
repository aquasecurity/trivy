package jar

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"

	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&javaLibraryAnalyzer{})
}

const version = 1

var requiredExtensions = []string{
	".jar",
	".war",
	".ear",
	".par",
}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct {
	once   sync.Once
	client *javadb.DB
}

func (a *javaLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// TODO: think about the sonatype API and "--offline"
	var err error
	a.once.Do(func() {
		log.Logger.Info("JAR files found")
		a.client, err = javadb.NewClient()
		if err != nil {
			log.Logger.Errorf("Unable to initialize the Java DB: %s", err)
			return
		}
		log.Logger.Info("Analyzing JAR files takes a while...")
	})
	if err != nil {
		return nil, err
	}

	// Skip analyzing JAR files as the nil client means the Java DB was not downloaded successfully.
	if a.client == nil {
		return nil, nil
	}

	p := jar.NewParser(a.client, jar.WithSize(input.Info.Size()), jar.WithFilePath(input.FilePath))
	libs, deps, err := p.Parse(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("jar/war/ear/par parse error: %w", err)
	}

	return language.ToAnalysisResult(types.Jar, input.FilePath, input.FilePath, libs, deps), nil
}

func (a *javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a *javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a *javaLibraryAnalyzer) Version() int {
	return version
}
