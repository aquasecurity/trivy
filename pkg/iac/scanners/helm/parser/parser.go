package parser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart"
	"helm.sh/helm/v4/pkg/chart/common"
	"helm.sh/helm/v4/pkg/chart/loader/archive"
	chartv2 "helm.sh/helm/v4/pkg/chart/v2"
	loaderv2 "helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/release"
	releaseutil "helm.sh/helm/v4/pkg/release/v1/util"

	"github.com/aquasecurity/trivy/pkg/log"
)

var manifestNameRegex = regexp.MustCompile("# Source: [^/]+/(.+)")

type Parser struct {
	logger       *log.Logger
	helmClient   *action.Install
	rootPath     string
	ChartSource  string
	filepaths    map[string]fs.FS
	archiveFiles []*archive.BufferedFile
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
	client.DryRunStrategy = action.DryRunClient // to avoid the client making calls to the server
	client.Replace = true                       // skip name check

	p := &Parser{
		helmClient:  client,
		ChartSource: src,
		logger:      log.WithPrefix("helm parser"),
		filepaths:   make(map[string]fs.FS),
	}

	for _, option := range opts {
		option(p)
	}

	if p.apiVersions != nil {
		p.helmClient.APIVersions = p.apiVersions
	}

	if p.kubeVersion != "" {
		kubeVersion, err := common.ParseKubeVersion(p.kubeVersion)
		if err != nil {
			return nil, err
		}

		p.helmClient.KubeVersion = kubeVersion
	}

	return p, nil
}

func (p *Parser) ParseFS(ctx context.Context, fsys fs.FS, target string) error {
	target = filepath.ToSlash(target)
	if err := fs.WalkDir(fsys, target, func(filePath string, entry fs.DirEntry, err error) error {
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
		return p.addPaths(fsys, filePath)
	}); err != nil {
		return fmt.Errorf("walk dir error: %w", err)
	}
	return nil
}

func (p *Parser) ParseArchive(_ context.Context, fsys fs.FS, archivePath string) error {
	f, err := fsys.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	files, err := archive.LoadArchiveFiles(f)
	if err != nil {
		return fmt.Errorf("load archive files: %w", err)
	}

	for _, file := range files {
		if file.Name == "Chart.yaml" {
			p.applyChartName(file.Data, "")
			break
		}
	}

	p.archiveFiles = files
	return nil
}

func (p *Parser) addPaths(fsys fs.FS, paths ...string) error {
	for _, filePath := range paths {
		if _, err := fs.Stat(fsys, filePath); err != nil {
			return err
		}

		if strings.HasSuffix(filePath, "Chart.yaml") && p.rootPath == "" {
			data, err := fs.ReadFile(fsys, filePath)
			if err != nil {
				return err
			}
			dir := filepath.Dir(filePath)
			if dir == "." {
				dir = ""
			}
			p.applyChartName(data, dir)
			p.rootPath = filepath.Dir(filePath)
		}
		p.filepaths[filePath] = fsys
	}
	return nil
}

func (p *Parser) applyChartName(data []byte, fallback string) {
	name, err := parseChartName(data)
	if err != nil {
		if fallback != "" {
			p.helmClient.ReleaseName = fallback
		} else {
			p.helmClient.ReleaseName = uuid.NewString()
		}
		return
	}
	p.helmClient.ReleaseName = name
}

func parseChartName(data []byte) (string, error) {
	var chartContent map[string]any
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&chartContent); err != nil {
		return "", err
	}
	name, ok := chartContent["name"]
	if !ok {
		return "", fmt.Errorf("could not extract the chart name from Chart.yaml")
	}
	return fmt.Sprintf("%v", name), nil
}

func (p *Parser) RenderedChartFiles() ([]ChartFile, error) {
	chrt, err := p.loadChart()
	if err != nil {
		return nil, err
	}

	acc, err := p.getRelease(chrt)
	if err != nil {
		return nil, err
	}

	splitManifests := releaseutil.SplitManifests(strings.TrimSpace(acc.Manifest()))
	manifestsKeys := make([]string, 0, len(splitManifests))
	for k := range splitManifests {
		manifestsKeys = append(manifestsKeys, k)
	}
	return p.getRenderedManifests(manifestsKeys, splitManifests), nil
}

func (p *Parser) getRelease(chrt *chartv2.Chart) (release.Accessor, error) {
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

	rel, err := p.helmClient.RunWithContext(context.Background(), chrt, vals)
	if err != nil {
		return nil, err
	}

	if rel == nil {
		return nil, errors.New("there is nothing in the release")
	}

	acc, err := release.NewAccessor(rel)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (p *Parser) loadChart() (*chartv2.Chart, error) {
	var files []*archive.BufferedFile

	if p.archiveFiles != nil {
		files = p.archiveFiles
	} else {
		for filePath, fsys := range p.filepaths {
			b, err := fs.ReadFile(fsys, filePath)
			if err != nil {
				return nil, err
			}
			filePath = strings.TrimPrefix(filePath, p.rootPath+"/")
			filePath = filepath.ToSlash(filePath)
			files = append(files, &archive.BufferedFile{
				Name: filePath,
				Data: b,
			})
		}
	}

	chrt, err := loaderv2.LoadFiles(files)
	if err != nil {
		return nil, err
	}

	if req := chrt.Metadata.Dependencies; req != nil {
		acc, err := chart.NewAccessor(chrt)
		if err != nil {
			return nil, err
		}

		if err := action.CheckDependencies(chrt, acc.MetaDependencies()); err != nil {
			return nil, err
		}
	}

	return chrt, nil
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
