package parser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

var manifestNameRegex = regexp.MustCompile("# Source: [^/]+/(.+)")

type Parser struct {
	helmClient   *action.Install
	rootPath     string
	ChartSource  string
	filepaths    []string
	debug        debug.Logger
	skipRequired bool
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

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "helm", "parser")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func (p *Parser) SetValuesFile(s ...string) {
	p.valuesFiles = s
}

func (p *Parser) SetValues(values ...string) {
	p.values = values
}

func (p *Parser) SetFileValues(values ...string) {
	p.fileValues = values
}

func (p *Parser) SetStringValues(values ...string) {
	p.stringValues = values
}

func (p *Parser) SetAPIVersions(values ...string) {
	p.apiVersions = values
}

func (p *Parser) SetKubeVersion(value string) {
	p.kubeVersion = value
}

func New(path string, opts ...options.ParserOption) (*Parser, error) {

	client := action.NewInstall(&action.Configuration{})
	client.DryRun = true     // don't do anything
	client.Replace = true    // skip name check
	client.ClientOnly = true // don't try to talk to a cluster

	p := &Parser{
		helmClient:  client,
		ChartSource: path,
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

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) error {
	p.workingFS = target

	if err := fs.WalkDir(p.workingFS, filepath.ToSlash(path), func(path string, entry fs.DirEntry, err error) error {
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

		if !p.required(path, p.workingFS) {
			return nil
		}

		if detection.IsArchive(path) {
			tarFS, err := p.addTarToFS(path)
			if errors.Is(err, errSkipFS) {
				// an unpacked Chart already exists
				return nil
			} else if err != nil {
				return fmt.Errorf("failed to add tar %q to FS: %w", path, err)
			}

			targetPath := filepath.Dir(path)
			if targetPath == "" {
				targetPath = "."
			}

			if err := p.ParseFS(ctx, tarFS, targetPath); err != nil {
				return fmt.Errorf("parse tar FS error: %w", err)
			}
			return nil
		} else {
			return p.addPaths(path)
		}
	}); err != nil {
		return fmt.Errorf("walk dir error: %w", err)
	}

	return nil
}

func (p *Parser) addPaths(paths ...string) error {
	for _, path := range paths {
		if _, err := fs.Stat(p.workingFS, path); err != nil {
			return err
		}

		if strings.HasSuffix(path, "Chart.yaml") && p.rootPath == "" {
			if err := p.extractChartName(path); err != nil {
				return err
			}
			p.rootPath = filepath.Dir(path)
		}
		p.filepaths = append(p.filepaths, path)
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
		return nil, fmt.Errorf("there is nothing in the release")
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

func (p *Parser) required(path string, workingFS fs.FS) bool {
	if p.skipRequired {
		return true
	}
	content, err := fs.ReadFile(workingFS, path)
	if err != nil {
		return false
	}

	return detection.IsType(path, bytes.NewReader(content), detection.FileTypeHelm)
}
