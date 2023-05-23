package jar

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJar, newJavaLibraryAnalyzer)
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
	slow   bool
}

func newJavaLibraryAnalyzer(options analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaLibraryAnalyzer{
		slow: options.Slow,
	}, nil
}

func (a *javaLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
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

	// It will be called on each JAR file
	onFile := func(path string, info fs.FileInfo, r dio.ReadSeekerAt) (*types.Application, error) {
		p := jar.NewParser(a.client, jar.WithSize(info.Size()), jar.WithFilePath(path))
		return language.ParsePackage(types.Jar, path, r, p, input.Options.FileChecksum)
	}

	var apps []types.Application
	onResult := func(app *types.Application) error {
		if app == nil {
			return nil
		}
		apps = append(apps, *app)
		return nil
	}

	if err = parallel.WalkDir(ctx, input.FS, ".", a.slow, onFile, onResult); err != nil {
		return nil, xerrors.Errorf("walk dir error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
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
