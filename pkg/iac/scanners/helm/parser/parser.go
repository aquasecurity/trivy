package parser

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/samber/lo"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/log"
)

var manifestNameRegex = regexp.MustCompile("# Source: [^/]+/(.+)")

type Parser struct {
	logger      *log.Logger
	helmClient  *action.Install
	valueOpts   ValueOptions
	apiVersions []string
	kubeVersion string

	vals map[string]any
}

type ChartFile struct {
	ChartPath string
	Path      string
	Content   string
}

func New(opts ...Option) (*Parser, error) {

	client := action.NewInstall(&action.Configuration{})
	client.DryRun = true     // don't do anything
	client.Replace = true    // skip name check
	client.ClientOnly = true // don't try to talk to a cluster

	p := &Parser{
		helmClient: client,
		logger:     log.WithPrefix("helm parser"),
	}

	for _, option := range opts {
		option(p)
	}

	if p.apiVersions != nil {
		p.helmClient.APIVersions = p.apiVersions
	}

	if p.kubeVersion != "" {
		kubeVersion, err := chartutil.ParseKubeVersion(p.kubeVersion)
		if err != nil {
			return nil, err
		}

		p.helmClient.KubeVersion = kubeVersion
	}

	vals, err := p.valueOpts.MergeValues()
	if err != nil {
		return nil, err
	}
	p.vals = vals
	return p, nil
}

type Chart struct {
	path string
	*chart.Chart
}

func (p *Parser) ParseFS(ctx context.Context, fsys fs.FS, root string) ([]ChartFile, error) {

	charts, err := p.collectCharts(fsys, root)
	if err != nil {
		return nil, err
	}

	var files []ChartFile
	for _, c := range charts {
		chartFiles, err := p.renderChart(c)
		if err != nil {
			p.logger.Error("Failed to render chart",
				log.String("name", c.Name()), log.FilePath(c.path), log.Err(err))
			continue
		}
		files = append(files, chartFiles...)
	}

	return files, nil
}

func (p *Parser) collectCharts(fsys fs.FS, root string) ([]Chart, error) {
	var charts []Chart

	walkDirFn := func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		switch {
		case strings.HasSuffix(filePath, "Chart.yaml"):
			c, err := loadChart(fsys, path.Dir(filePath))
			if err != nil {
				p.logger.Error("Failed to load chart", log.FilePath(filePath), log.Err(err))
				return fs.SkipDir
			}

			charts = append(charts, Chart{
				Chart: c,
				path:  path.Dir(filePath),
			})
			return fs.SkipDir
		case detection.IsZip(filePath):
			c, err := loadArchivedChart(fsys, filePath)
			if err != nil {
				p.logger.Error("Failed to load chart", log.FilePath(filePath), log.Err(err))
				return nil
			}

			if c == nil {
				return nil
			}

			charts = append(charts, Chart{
				Chart: c,
				path:  filePath,
			})
		}

		return nil
	}

	if err := fs.WalkDir(fsys, root, walkDirFn); err != nil {
		return nil, err
	}

	return charts, nil
}

func (p *Parser) resolveReleaseName(c *chart.Chart) {
	p.helmClient.ReleaseName = extractChartName(c)
}

func extractChartName(c *chart.Chart) string {
	if c.Metadata == nil {
		return uuid.NewString()
	}

	return c.Metadata.Name
}

func (p *Parser) renderChart(c Chart) ([]ChartFile, error) {
	if req := c.Metadata.Dependencies; req != nil {
		if err := action.CheckDependencies(c.Chart, req); err != nil {
			return nil, err
		}
	}

	r, err := p.getRelease(c)
	if err != nil {
		return nil, err
	}

	return getRenderedManifests(c.path, r.Manifest), nil
}

func (p *Parser) getRelease(c Chart) (*release.Release, error) {
	p.resolveReleaseName(c.Chart)
	defer func() { p.helmClient.ReleaseName = "" }()

	r, err := p.helmClient.RunWithContext(context.Background(), c.Chart, p.vals)
	if err != nil {
		return nil, err
	}

	if r == nil {
		return nil, fmt.Errorf("there is nothing in the release")
	}
	return r, nil
}

func getRenderedManifests(chartPath, manifest string) []ChartFile {
	entries := releaseutil.SplitManifests(strings.TrimSpace(manifest))
	keys := lo.Keys(entries)

	sort.Sort(releaseutil.BySplitManifestsOrder(keys))

	files := make([]ChartFile, 0, len(keys))
	for _, key := range keys {
		entry := entries[key]
		submatch := manifestNameRegex.FindStringSubmatch(entry)
		if len(submatch) == 0 {
			continue
		}
		files = append(files, ChartFile{
			ChartPath: chartPath,
			Path:      getManifestPath(entry),
			Content:   entry,
		})
	}
	return files
}

func getManifestPath(manifest string) string {
	lines := strings.Split(manifest, "\n")
	if len(lines) == 0 {
		return "unknown.yaml"
	}
	parts := strings.SplitN(strings.TrimPrefix(lines[0], "# Source: "), "/", 2)
	if len(parts) > 1 {
		return parts[1]
	}
	return parts[0]
}

func loadChart(fsys fs.FS, root string) (*chart.Chart, error) {

	var files []*loader.BufferedFile

	walkFn := func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		b, err := fs.ReadFile(fsys, filePath)
		if err != nil {
			return err
		}

		filePath = filepath.ToSlash(filePath)
		filePath = strings.TrimPrefix(filePath, root+"/")
		files = append(files, &loader.BufferedFile{Name: filePath, Data: b})

		return nil
	}

	if err := fs.WalkDir(fsys, root, walkFn); err != nil {
		return nil, err
	}

	c, err := loader.LoadFiles(files)
	if err != nil {
		return nil, err
	}

	return c, err
}

func loadArchivedChart(fsys fs.FS, filePath string) (*chart.Chart, error) {
	ok, err := archivedChartNextToUnpacked(fsys, filePath)
	if err != nil {
		return nil, err
	}

	// skip if unpacked Chart exists
	// we can avoid duplicate results if the user packaged Chart and scans this directory
	if ok {
		return nil, nil
	}

	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return loader.LoadArchive(f)
}

func archivedChartNextToUnpacked(fsys fs.FS, filePath string) (bool, error) {
	f, err := fsys.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return false, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	header, err := tr.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get next entry: %w", err)
	}

	name := filepath.ToSlash(header.Name)

	// helm package . or helm package <dir>
	chartPaths := []string{
		path.Join(filePath, "..", "Chart.yaml"),
		path.Join(filePath, "..", path.Dir(name), "Chart.yaml"),
	}

	for _, chartPath := range chartPaths {
		_, err := fs.Stat(fsys, chartPath)
		if err == nil {
			return true, nil
		}
	}
	return false, nil
}
