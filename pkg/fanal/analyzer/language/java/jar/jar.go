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
)

func init() {
	analyzer.RegisterPostAnalyzer(&javaLibraryAnalyzer{})
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

func (a *javaLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
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

	var apps []types.Application
	err = fs.WalkDir(input.FS, ".", func(path string, d fs.DirEntry, err error) error {
		info, err := d.Info()
		if err != nil {
			return err
		}
		f, err := input.FS.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		r, ok := f.(dio.ReadSeekerAt)
		if !ok {
			return xerrors.New("type assertion failed")
		}
		p := jar.NewParser(a.client, jar.WithSize(info.Size()), jar.WithFilePath(path))
		libs, deps, err := p.Parse(r)
		if err != nil {
			return xerrors.Errorf("jar/war/ear/par parse error: %w", err)
		}

		app := language.ToApplication(types.Jar, path, path, libs, deps)
		if app == nil {
			return nil
		}
		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
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
