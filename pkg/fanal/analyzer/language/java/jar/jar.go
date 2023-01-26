package jar

import (
	"context"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/oci"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
)

func init() {
	analyzer.RegisterAnalyzer(&javaLibraryAnalyzer{})
}

const (
	version   = 1
	mediaType = "application/vnd.aquasec.trivy.java.db.layer.v1.tar+gzip"
	repo      = "ghcr.io/dmitriylewen/trivy-java-db:latest"
)

var requiredExtensions = []string{".jar", ".war", ".ear", ".par"}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct{}

func (a javaLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := jar.NewParser(jar.WithSize(input.Info.Size()), jar.WithFilePath(input.FilePath), jar.WithOffline(input.Options.Offline))
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
			cacheDir := "/home/dmitriy/.cache/trivy/java-db" // TODO change this
			c := metadata.NewClient(cacheDir)
			meta, err := c.Get()
			if err != nil || meta.NextUpdate.Before(time.Now().UTC()) {
				err = downloadTrivyJavaDB(filepath.Join(cacheDir, "db"), false, false) // TODO add flags
				if err != nil {
					log.Logger.Warn("can't download trivy-java-db: %w", err)
				}
			}
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

func downloadTrivyJavaDB(cacheDir string, quiet, insecure bool) error {
	artifact, err := oci.NewArtifact(repo, mediaType, quiet, insecure)
	if err != nil {
		return xerrors.Errorf("trivy-java-db artifact initialize error: %w", err) // TODO change this!!!
	}
	err = artifact.Download(context.Background(), cacheDir)
	if err != nil {
		return xerrors.Errorf("trivy-java-db download error: %w", err)
	}
	return nil
}
