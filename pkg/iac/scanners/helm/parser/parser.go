package parser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
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
	logger       *log.Logger
	helmClient   *action.Install
	rootPath     string
	ChartSource  string
	filepaths    []string
	workingFS    fs.FS
	valuesFiles  []string
	values       []string
	fileValues   []string
	stringValues []string
	apiVersions  []string
	kubeVersion  string
}

type ChartFile struct {
	TemplateFilePath string
	ManifestContent  string
}

func New(src string, opts ...Option) (*Parser, error) {

	client := action.NewInstall(&action.Configuration{})
	client.DryRun = true     // don't do anything
	client.Replace = true    // skip name check
	client.ClientOnly = true // don't try to talk to a cluster

	p := &Parser{
		helmClient:  client,
		ChartSource: src,
		logger:      log.WithPrefix("helm parser"),
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

	return p, nil
}

func (p *Parser) ParseFS(ctx context.Context, fsys fs.FS, target string) error {
	p.workingFS = fsys

	if err := fs.WalkDir(p.workingFS, filepath.ToSlash(target), func(filePath string, entry fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		if _, err := fs.Stat(p.workingFS, filePath); err != nil {
			return nil
		}

		if detection.IsArchive(filePath) && !isDependencyChartArchive(p.workingFS, filePath) {
			tarFS, err := p.addTarToFS(filePath)
			if errors.Is(err, errSkipFS) {
				// an unpacked Chart already exists
				return nil
			} else if err != nil {
				return fmt.Errorf("failed to add tar %q to FS: %w", filePath, err)
			}

			targetPath := filepath.Dir(filePath)
			if targetPath == "" {
				targetPath = "."
			}

			if err := p.ParseFS(ctx, tarFS, targetPath); err != nil {
				return fmt.Errorf("parse tar FS error: %w", err)
			}
			return nil
		} else {
			return p.addPaths(filePath)
		}
	}); err != nil {
		return fmt.Errorf("walk dir error: %w", err)
	}

	return nil
}

func isDependencyChartArchive(fsys fs.FS, archivePath string) bool {
	parent := path.Dir(archivePath)
	if path.Base(parent) != "charts" {
		return false
	}

	_, err := fs.Stat(fsys, path.Join(parent, "..", "Chart.yaml"))
	return err == nil
}

func (p *Parser) addPaths(paths ...string) error {
	for _, filePath := range paths {
		if _, err := fs.Stat(p.workingFS, filePath); err != nil {
			return err
		}

		if strings.HasSuffix(filePath, "Chart.yaml") && p.rootPath == "" {
			if err := p.extractChartName(filePath); err != nil {
				return err
			}
			p.rootPath = filepath.Dir(filePath)
		}
		p.filepaths = append(p.filepaths, filePath)
	}
	return nil
}

func (p *Parser) extractChartName(chartPath string) error {

	chrt, err := p.workingFS.Open(chartPath)
	if err != nil {
		return err
	}
	defer func() { _ = chrt.Close() }()

	var chartContent map[string]any
	if err := yaml.NewDecoder(chrt).Decode(&chartContent); err != nil {
		// the chart likely has the name templated and so cannot be parsed as yaml - use a temporary name
		if dir := filepath.Dir(chartPath); dir != "" && dir != "." {
			p.helmClient.ReleaseName = dir
		} else {
			p.helmClient.ReleaseName = uuid.NewString()
		}
		return nil
	}

	if name, ok := chartContent["name"]; !ok {
		return fmt.Errorf("could not extract the chart name from %s", chartPath)
	} else {
		p.helmClient.ReleaseName = fmt.Sprintf("%v", name)
	}
	return nil
}

func (p *Parser) RenderedChartFiles() ([]ChartFile, error) {
	workingChart, err := p.loadChart()
	if err != nil {
		return nil, err
	}

	workingRelease, err := p.getRelease(workingChart)
	if err != nil {
		return nil, err
	}

	var manifests bytes.Buffer
	_, _ = fmt.Fprintln(&manifests, strings.TrimSpace(workingRelease.Manifest))

	splitManifests := releaseutil.SplitManifests(manifests.String())
	manifestsKeys := make([]string, 0, len(splitManifests))
	for k := range splitManifests {
		manifestsKeys = append(manifestsKeys, k)
	}
	return p.getRenderedManifests(manifestsKeys, splitManifests), nil
}

func (p *Parser) getRelease(chrt *chart.Chart) (*release.Release, error) {
	opts := &ValueOptions{
		ValueFiles:   p.valuesFiles,
		Values:       p.values,
		FileValues:   p.fileValues,
		StringValues: p.stringValues,
	}

	vals, err := opts.MergeValues()
	if err != nil {
		return nil, err
	}
	r, err := p.helmClient.RunWithContext(context.Background(), chrt, vals)
	if err != nil {
		return nil, err
	}

	if r == nil {
		return nil, errors.New("there is nothing in the release")
	}
	return r, nil
}

func (p *Parser) loadChart() (*chart.Chart, error) {

	var files []*loader.BufferedFile

	for _, filePath := range p.filepaths {
		b, err := fs.ReadFile(p.workingFS, filePath)
		if err != nil {
			return nil, err
		}

		filePath = strings.TrimPrefix(filePath, p.rootPath+"/")
		filePath = filepath.ToSlash(filePath)
		files = append(files, &loader.BufferedFile{
			Name: filePath,
			Data: b,
		})
	}

	c, err := loader.LoadFiles(files)
	if err != nil {
		return nil, err
	}

	if req := c.Metadata.Dependencies; req != nil {
		if err := action.CheckDependencies(c, req); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (*Parser) getRenderedManifests(manifestsKeys []string, splitManifests map[string]string) []ChartFile {
	sort.Sort(releaseutil.BySplitManifestsOrder(manifestsKeys))
	var manifestsToRender []ChartFile
	for _, manifestKey := range manifestsKeys {
		manifest := splitManifests[manifestKey]
		submatch := manifestNameRegex.FindStringSubmatch(manifest)
		if len(submatch) == 0 {
			continue
		}
		manifestsToRender = append(manifestsToRender, ChartFile{
			TemplateFilePath: getManifestPath(manifest),
			ManifestContent:  manifest,
		})
	}
	return manifestsToRender
}

func getManifestPath(manifest string) string {
	lines := strings.Split(manifest, "\n")
	if len(lines) == 0 {
		return "unknown.yaml"
	}
	manifestFilePathParts := strings.SplitN(strings.TrimPrefix(lines[0], "# Source: "), "/", 2)
	if len(manifestFilePathParts) > 1 {
		return manifestFilePathParts[1]
	}
	return manifestFilePathParts[0]
}
