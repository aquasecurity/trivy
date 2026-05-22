package helm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	chartutilv2 "helm.sh/helm/v4/pkg/chart/v2/util"

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
	"github.com/aquasecurity/trivy/pkg/mapfs"
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

type chartLocation struct {
	path      string
	isArchive bool
}

func locateCharts(ctx context.Context, fsys fs.FS, dir string) ([]chartLocation, error) {
	var locations []chartLocation
	err := fs.WalkDir(fsys, dir, func(filePath string, d fs.DirEntry, err error) error {
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
			if shouldSkipArchive(fsys, filePath) {
				return nil
			}
			locations = append(locations, chartLocation{path: filePath, isArchive: true})
		} else if path.Base(filePath) == chartutilv2.ChartfileName {
			locations = append(locations, chartLocation{path: path.Dir(filePath)})
			return fs.SkipDir
		}

		return nil
	})
	return locations, err
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	locations, err := locateCharts(ctx, fsys, dir)
	if err != nil {
		return nil, err
	}

	var results []scan.Result
	for _, loc := range locations {
		scanResults, err := s.scanChart(ctx, loc, fsys)
		if err != nil {
			return nil, err
		}
		results = append(results, scanResults...)
	}
	return results, nil
}

func shouldSkipArchive(fsys fs.FS, archivePath string) bool {
	return hasChartYaml(fsys, path.Dir(archivePath)) || unpackedChartExists(fsys, archivePath)
}

func hasChartYaml(fsys fs.FS, dir string) bool {
	_, err := fs.Stat(fsys, path.Join(dir, "Chart.yaml"))
	return err == nil
}

func unpackedChartExists(fsys fs.FS, archivePath string) bool {
	f, err := fsys.Open(archivePath)
	if err != nil {
		return false
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer gz.Close()

	hdr, err := tar.NewReader(gz).Next()
	if err != nil {
		return false
	}

	firstComponent := strings.SplitN(filepath.ToSlash(hdr.Name), "/", 2)[0]
	if firstComponent == "" {
		return false
	}

	_, err = fs.Stat(fsys, path.Join(path.Dir(archivePath), firstComponent))
	return err == nil
}

func (s *Scanner) scanChart(ctx context.Context, loc chartLocation, target fs.FS) (results []scan.Result, err error) {
	helmParser, err := parser.New(s.parserOptions...)
	if err != nil {
		return nil, err
	}

	var manifests []parser.Manifest
	if loc.isArchive {
		manifests, err = helmParser.ParseArchive(ctx, target, loc.path)
	} else {
		manifests, err = helmParser.ParseFS(ctx, target, loc.path)
	}
	if err != nil { // not valid helm, maybe some other yaml etc., abort
		s.logger.Error(
			"Failed to render Chart files",
			log.FilePath(loc.path), log.Err(err),
		)
		return nil, nil
	}

	rs, err := s.InitRegoScanner(target, s.options)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	for _, file := range manifests {
		s.logger.Debug("Processing rendered chart file", log.FilePath(file.Path))

		ignoreRules := ignore.Parse(file.Content, file.Path, loc.path)
		k8sManifests, err := kparser.Parse(ctx, strings.NewReader(file.Content), file.Path)
		if err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}

		manifestFS := mapfs.New()
		if err := manifestFS.MkdirAll(path.Dir(file.Path), fs.ModePerm); err != nil {
			return nil, err
		}
		if err := manifestFS.WriteVirtualFile(file.Path, []byte(file.Content), fs.ModePerm); err != nil {
			return nil, err
		}

		for _, manifest := range k8sManifests {
			fileResults, err := rs.ScanInput(ctx, types.SourceKubernetes, rego.Input{
				Path:     file.Path,
				Contents: manifest.ToRego(),
				FS:       manifestFS,
			})
			if err != nil {
				return nil, fmt.Errorf("scanning error: %w", err)
			}

			fileResults.SetSourceAndFilesystem(loc.path, manifestFS, loc.isArchive)
			fileResults.Ignore(ignoreRules, nil)

			results = append(results, fileResults...)
		}
	}
	return results, nil
}
