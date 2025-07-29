package helm

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/liamg/memoryfs"
	"helm.sh/helm/v3/pkg/chartutil"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
	kparser "github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	*rego.RegoScannerProvider
	logger        *log.Logger
	options       []options.ScannerOption
	parserOptions []parser.Option
}

// New creates a new Scanner
func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		RegoScannerProvider: rego.NewRegoScannerProvider(opts...),
		options:             opts,
		logger:              log.WithPrefix("helm scanner"),
	}

	for _, option := range opts {
		option(s)
	}
	return s
}

func (s *Scanner) addParserOptions(opts ...parser.Option) {
	s.parserOptions = append(s.parserOptions, opts...)
}

func (s *Scanner) Name() string {
	return "Helm"
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	var results []scan.Result
	if err := fs.WalkDir(fsys, dir, func(filePath string, d fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if detection.IsArchive(filePath) {
			scanResults, err := s.getScanResults(ctx, filePath, fsys)
			if err != nil {
				return err
			}
			results = append(results, scanResults...)
		} else if path.Base(filePath) == chartutil.ChartfileName {
			if scanResults, err := s.getScanResults(ctx, filepath.Dir(filePath), fsys); err != nil {
				return err
			} else {
				results = append(results, scanResults...)
			}
			return fs.SkipDir
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return results, nil

}

func (s *Scanner) getScanResults(ctx context.Context, path string, target fs.FS) (results []scan.Result, err error) {
	helmParser, err := parser.New(path, s.parserOptions...)
	if err != nil {
		return nil, err
	}

	if err := helmParser.ParseFS(ctx, target, path); err != nil {
		return nil, err
	}

	chartFiles, err := helmParser.RenderedChartFiles()
	if err != nil { // not valid helm, maybe some other yaml etc., abort
		s.logger.Error(
			"Failed to render Chart files",
			log.FilePath(path), log.Err(err),
		)
		return nil, nil
	}

	rs, err := s.InitRegoScanner(target, s.options)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	for _, file := range chartFiles {
		s.logger.Debug("Processing rendered chart file", log.FilePath(file.TemplateFilePath))

		ignoreRules := ignore.Parse(file.ManifestContent, file.TemplateFilePath, "")
		manifests, err := kparser.Parse(ctx, strings.NewReader(file.ManifestContent), file.TemplateFilePath)
		if err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		for _, manifest := range manifests {
			fileResults, err := rs.ScanInput(ctx, types.SourceKubernetes, rego.Input{
				Path:     file.TemplateFilePath,
				Contents: manifest,
				FS:       target,
			})
			if err != nil {
				return nil, fmt.Errorf("scanning error: %w", err)
			}

			if len(fileResults) > 0 {
				renderedFS := memoryfs.New()
				if err := renderedFS.MkdirAll(filepath.Dir(file.TemplateFilePath), fs.ModePerm); err != nil {
					return nil, err
				}
				if err := renderedFS.WriteLazyFile(file.TemplateFilePath, func() (io.Reader, error) {
					return strings.NewReader(file.ManifestContent), nil
				}, fs.ModePerm); err != nil {
					return nil, err
				}
				fileResults.SetSourceAndFilesystem(helmParser.ChartSource, renderedFS, detection.IsArchive(helmParser.ChartSource))
				fileResults.Ignore(ignoreRules, nil)
			}

			results = append(results, fileResults...)
		}

	}
	return results, nil
}
