package eval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/log"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

type ModuleResolver struct {
	logger *log.Logger
	client *http.Client

	allowDownloads    bool
	skipCachedModules bool

	modMetadata *ModulesMetadata
	rootPath    string
}

type ModResolverOption func(r *ModuleResolver)

func WithAllowDownloads(allow bool) ModResolverOption {
	return func(r *ModuleResolver) {
		r.allowDownloads = allow
	}
}

func WithSkipCachedModules(skip bool) ModResolverOption {
	return func(r *ModuleResolver) {
		r.skipCachedModules = skip
	}
}

func NewModuleResolver(logger *log.Logger, opts ...ModResolverOption) *ModuleResolver {
	r := &ModuleResolver{
		logger: logger,
		client: xhttp.Client(xhttp.WithTimeout(5 * time.Second)),
	}

	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *ModuleResolver) Resolve(ctx context.Context, fsys fs.FS, root string) (*ModuleConfig, error) {
	r.rootPath = root

	fakeCall := ModuleCall{
		Name:   "root",
		Source: "./",
		FS:     fsys,
		Path:   root,
	}

	modMetadata, metadataPath, err := loadModuleMetadata(fsys, root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		r.logger.Error("Error loading module metadata", log.Err(err))
	} else if err == nil {
		r.logger.Debug("Loaded module metadata",
			log.FilePath(metadataPath),
			log.Int("count", len(modMetadata.Modules)),
		)
	}
	r.modMetadata = modMetadata

	rootCfg, err := r.resolveChildren(ctx, &fakeCall, RootModule, "")
	if err != nil {
		return rootCfg, err
	}
	rootCfg.Name = "root"
	rootCfg.FS = fsys
	rootCfg.Dir = root

	return rootCfg, nil
}

func (r *ModuleResolver) resolveChildren(ctx context.Context, mc *ModuleCall, addr ModuleAddr, parentLogicalSource string) (*ModuleConfig, error) {
	mod, err := r.loadModule(ctx, addr, mc, parentLogicalSource)
	if err != nil {
		return nil, err
	}

	for _, childMc := range mod.ModuleCalls {
		child, err := r.resolveChildren(ctx, childMc, addr.Call(childMc.Name), mod.LogicalSource)
		if err != nil {
			return nil, err
		}
		child.Parent = mod
		child.Name = childMc.Name
		child.FS = childMc.FS
		child.Dir = childMc.Path
		child.Block = childMc.Config
		mod.Children = append(mod.Children, child)
	}
	return mod, nil
}

func (r *ModuleResolver) loadModule(ctx context.Context, addr ModuleAddr, mc *ModuleCall, parentLogicalSource string) (*ModuleConfig, error) {
	if r.modMetadata != nil {
		mod, err := r.loadModuleFromTerraformCache(ctx, addr, mc)
		if err == nil {
			r.logger.Debug("Using module from Terraform cache .terraform/modules",
				log.String("source", mc.Source))
			return mod, nil
		}
	}

	mod, err := r.loadExternalModule(ctx, addr, mc, parentLogicalSource)
	if err != nil {
		return nil, err
	}
	return mod, nil
}

func (r *ModuleResolver) loadExternalModule(ctx context.Context, addr ModuleAddr, mc *ModuleCall, parentLogicalSource string) (*ModuleConfig, error) {
	r.logger.Debug("Resolve module", log.String("source", mc.Source))

	opt := resolvers.Options{
		Source:          mc.Source,
		OriginalSource:  mc.Source,
		Version:         mc.Version,
		OriginalVersion: mc.Version,
		WorkingDir:      r.rootPath,
		Name:            addr.Key(),
		ModulePath:      mc.Path,
		Logger:          r.logger,
		AllowDownloads:  r.allowDownloads,
		SkipCache:       r.skipCachedModules,
	}

	fsys, source, downloadPath, err := resolvers.ResolveModule(ctx, mc.FS, opt)
	if err != nil {
		return nil, err
	}

	logicalSource := path.Join(parentLogicalSource, source)
	r.logger.Debug("Remote module resolved",
		log.String("addr", addr.Key()),
		log.String("source", mc.Source),
		log.String("logicalSource", logicalSource),
		log.FilePath(downloadPath),
	)

	return r.resolveLocal(ctx, fsys, downloadPath, logicalSource)
}

func (r *ModuleResolver) loadModuleFromTerraformCache(ctx context.Context, addr ModuleAddr, mc *ModuleCall) (*ModuleConfig, error) {
	moduleKey := strings.Join(addr, ".")
	var modulePath string
	for _, module := range r.modMetadata.Modules {
		if module.Key == moduleKey {
			modulePath = path.Clean(path.Join(r.rootPath, module.Dir))
			break
		}
	}
	if modulePath == "" {
		return nil, fmt.Errorf("resolve module with key %q from .terraform/modules", moduleKey)
	}

	logicalSource := mc.Source
	if strings.HasPrefix(mc.Source, ".") {
		logicalSource = ""
	}

	r.logger.Debug("Module resolved using modules.json",
		log.String("addr", addr.Key()),
		log.String("source", mc.Source),
		log.String("modulePath", modulePath),
	)

	return r.resolveLocal(ctx, mc.FS, modulePath, logicalSource)
}

func (r *ModuleResolver) resolveLocal(_ context.Context, fsys fs.FS, dir string, logicalSource string) (*ModuleConfig, error) {
	p := NewParser()
	cfg, err := p.ParseDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	cfg.LogicalSource = logicalSource
	r.logger.Debug("Module loaded", log.Any("fsys", fsys), log.FilePath(dir))
	return cfg, nil
}

const ManifestSnapshotFile = ".terraform/modules/modules.json"

type ModulesMetadata struct {
	Modules []ModuleMetadata `json:"Modules"`
}

type ModuleMetadata struct {
	Key     string `json:"Key"`
	Source  string `json:"Source"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

func loadModuleMetadata(fsys fs.FS, dir string) (*ModulesMetadata, string, error) {
	metadataPath := path.Join(dir, ManifestSnapshotFile)

	f, err := fsys.Open(metadataPath)
	if err != nil {
		return nil, metadataPath, err
	}
	defer f.Close()

	var metadata ModulesMetadata
	if err := json.NewDecoder(f).Decode(&metadata); err != nil {
		return nil, metadataPath, err
	}

	return &metadata, metadataPath, nil
}
