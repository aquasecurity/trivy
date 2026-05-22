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
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart"
	"helm.sh/helm/v4/pkg/chart/common"
	"helm.sh/helm/v4/pkg/chart/loader/archive"
	chartv2 "helm.sh/helm/v4/pkg/chart/v2"
	loaderv2 "helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutilv2 "helm.sh/helm/v4/pkg/chart/v2/util"
	"helm.sh/helm/v4/pkg/release"
	releaseutil "helm.sh/helm/v4/pkg/release/v1/util"

	"github.com/aquasecurity/trivy/pkg/log"
)

var manifestNameRegex = regexp.MustCompile("# Source: [^/]+/(.+)")

type Parser struct {
	logger       *log.Logger
	helmClient   *action.Install
	valuesFiles  []string
	values       []string
	fileValues   []string
	stringValues []string
	apiVersions  []string
	kubeVersion  string
}

// Manifest is a rendered Helm template — the output of helm template for a single Kubernetes resource.
type Manifest struct {
	Path    string
	Content string
}

func New(opts ...Option) (*Parser, error) {
	client := action.NewInstall(&action.Configuration{})
	client.DryRunStrategy = action.DryRunClient // to avoid the client making calls to the server
	client.Replace = true                       // skip name check

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
		kubeVersion, err := common.ParseKubeVersion(p.kubeVersion)
		if err != nil {
			return nil, err
		}

		p.helmClient.KubeVersion = kubeVersion
	}

	return p, nil
}

// ParseFS renders a Helm chart from a directory rooted at target within fsys.
func (p *Parser) ParseFS(ctx context.Context, fsys fs.FS, target string) ([]Manifest, error) {
	var rootPath string
	filepaths := make(map[string]fs.FS)

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

		if strings.HasSuffix(filePath, chartutilv2.ChartfileName) && rootPath == "" {
			data, err := fs.ReadFile(fsys, filePath)
			if err != nil {
				return err
			}
			dir := path.Dir(filePath)
			if dir == "." {
				dir = ""
			}
			p.applyChartName(data, dir)
			rootPath = path.Dir(filePath)
		}
		filepaths[filePath] = fsys
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk dir error: %w", err)
	}

	var files []*archive.BufferedFile
	for filePath, fsys := range filepaths {
		b, err := fs.ReadFile(fsys, filePath)
		if err != nil {
			return nil, err
		}
		filePath = strings.TrimPrefix(filePath, rootPath+"/")
		filePath = filepath.ToSlash(filePath)
		files = append(files, &archive.BufferedFile{
			Name: filePath,
			Data: b,
		})
	}

	return p.render(ctx, files)
}

// ParseArchive renders a Helm chart from a gzip-compressed tar archive within fsys.
func (p *Parser) ParseArchive(ctx context.Context, fsys fs.FS, archivePath string) ([]Manifest, error) {
	f, err := fsys.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	files, err := archive.LoadArchiveFiles(f)
	if err != nil {
		return nil, fmt.Errorf("load archive files: %w", err)
	}

	for _, file := range files {
		if file.Name == chartutilv2.ChartfileName {
			p.applyChartName(file.Data, "")
			break
		}
	}

	return p.render(ctx, files)
}

func (p *Parser) applyChartName(data []byte, fallback string) {
	if name, err := parseChartName(data); err == nil {
		p.helmClient.ReleaseName = name
		return
	}
	if fallback != "" {
		p.helmClient.ReleaseName = fallback
	} else {
		p.helmClient.ReleaseName = uuid.NewString()
	}
}

func parseChartName(data []byte) (string, error) {
	var meta struct {
		Name string `yaml:"name"`
	}
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&meta); err != nil {
		return "", err
	}
	if meta.Name == "" {
		return "", errors.New("could not extract the chart name from Chart.yaml")
	}
	return meta.Name, nil
}

func (p *Parser) render(ctx context.Context, files []*archive.BufferedFile) ([]Manifest, error) {
	chrt, err := p.loadChart(files)
	if err != nil {
		return nil, err
	}

	acc, err := p.getRelease(ctx, chrt)
	if err != nil {
		return nil, err
	}

	manifests := releaseutil.SplitManifests(strings.TrimSpace(acc.Manifest()))
	keys := make([]string, 0, len(manifests))
	for k := range manifests {
		keys = append(keys, k)
	}
	sort.Sort(releaseutil.BySplitManifestsOrder(keys))

	var result []Manifest
	for _, key := range keys {
		manifest := manifests[key]
		submatch := manifestNameRegex.FindStringSubmatch(manifest)
		if submatch == nil {
			continue
		}
		result = append(result, Manifest{
			Path:    submatch[1],
			Content: manifest,
		})
	}
	return result, nil
}

func (p *Parser) getRelease(ctx context.Context, chrt *chartv2.Chart) (release.Accessor, error) {
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

	rel, err := p.helmClient.RunWithContext(ctx, chrt, vals)
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

func (p *Parser) loadChart(files []*archive.BufferedFile) (*chartv2.Chart, error) {
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
