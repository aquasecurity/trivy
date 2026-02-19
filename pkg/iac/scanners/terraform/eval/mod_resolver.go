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

type moduleResolver struct {
	logger *log.Logger
	client *http.Client

	allowDownloads    bool
	skipCachedModules bool
	stopOnHCLError    bool
	skipPaths         []string

	modMetadata *ModulesMetadata
	rootPath    string
}

type ModResolverOption func(r *moduleResolver)

func WithAllowDownloads(allow bool) ModResolverOption {
	return func(r *moduleResolver) {
		r.allowDownloads = allow
	}
}

func WithSkipCachedModules(skip bool) ModResolverOption {
	return func(r *moduleResolver) {
		r.skipCachedModules = skip
	}
}

func WithStopOnHCLError(stop bool) ModResolverOption {
	return func(r *moduleResolver) {
		r.stopOnHCLError = stop
	}
}

func WithSkipPaths(dirs []string) ModResolverOption {
	return func(r *moduleResolver) {
		r.skipPaths = dirs
	}
}

func newModuleResolver(logger *log.Logger, opts ...ModResolverOption) *moduleResolver {
	r := &moduleResolver{
		logger: logger,
		client: xhttp.Client(xhttp.WithTimeout(5 * time.Second)),
	}

	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *moduleResolver) resolve(ctx context.Context, fsys fs.FS, root string) (*ModuleConfig, error) {
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
	rootCfg.Path = root

	return rootCfg, nil
}

func (r *moduleResolver) resolveChildren(ctx context.Context, mc *ModuleCall, addr ModuleAddr, sourceChain SourceChain) (*ModuleConfig, error) {
	mod, err := r.loadModule(ctx, addr, mc, sourceChain)
	if err != nil {
		r.logger.Error("Failed to load module",
			log.String("addr", addr.Key()),
			log.String("source", mc.Source),
			log.Err(err))

		// If the module fails to load, we return the module configuration without any blocks or module calls.
		// We do not return an error message, which allows us to partially evaluate the configuration of the module
		// that called this one. All output variables of such a module will be considered dynamic.
		// We also mark the configuration as unresolvable.
		// This flag is only used when building Terraform models for scanning and is ignored during evaluation.
		return &ModuleConfig{
			ModuleCalls:  make(map[string]*ModuleCall),
			Unresolvable: true,
		}, nil
	}

	for _, childMc := range mod.ModuleCalls {
		child, err := r.resolveChildren(ctx, childMc, addr.Call(childMc.Name), mod.SourceChain)
		if err != nil {
			return nil, err
		}
		child.Parent = mod
		child.Name = childMc.Name
		child.Config = childMc.Config
		mod.Children = append(mod.Children, child)
	}
	return mod, nil
}

func (r *moduleResolver) loadModule(ctx context.Context, addr ModuleAddr, mc *ModuleCall, sourceChain SourceChain) (*ModuleConfig, error) {
	if r.modMetadata != nil {
		mod, ok := r.loadModuleFromTerraformCache(ctx, addr, mc)
		// if for some reason it was not possible to load the module from the cache,
		// then ignore the error and try to load it in the usual way.
		if ok {
			r.logger.Debug("Using module from Terraform cache .terraform/modules",
				log.String("source", mc.Source))
			return mod, nil
		}
	}

	mod, err := r.loadModuleFromSource(ctx, addr, mc, sourceChain)
	if err != nil {
		return nil, err
	}
	return mod, nil
}

func (r *moduleResolver) loadModuleFromSource(ctx context.Context, addr ModuleAddr, mc *ModuleCall, sourceChain SourceChain) (*ModuleConfig, error) {
	logger := r.logger.With(
		log.String("addr", addr.Key()),
		log.String("source", mc.Source),
	)
	logger.Debug("Start resolving module")

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

	sourceChain = sourceChain.Extend(source)
	logger.Debug("Module resolved",
		log.String("sourceChain", string(sourceChain)),
		log.FilePath(downloadPath),
	)
	return r.loadModuleFromFS(ctx, fsys, downloadPath, sourceChain)
}

func (r *moduleResolver) loadModuleFromTerraformCache(ctx context.Context, addr ModuleAddr, mc *ModuleCall) (*ModuleConfig, bool) {
	moduleKey := strings.Join(addr, ".")
	modulePath := r.modMetadata.ModulePath(r.rootPath, moduleKey)

	if modulePath == "" {
		return nil, false
	}

	r.logger.Debug("Module loaded from Terraform cache",
		log.String("address", addr.Key()),
		log.String("source", mc.Source),
		log.String("key", moduleKey),
		log.FilePath(modulePath),
	)

	mod, err := r.loadModuleFromFS(ctx, mc.FS, modulePath, NewSourceChain(mc.Source))
	return mod, err == nil
}

func (r *moduleResolver) loadModuleFromFS(_ context.Context, fsys fs.FS, dir string, sourceChain SourceChain) (*ModuleConfig, error) {
	moduleLogger := r.logger.With(
		log.Prefix("module-parser"),
		log.String("sourceChain", string(sourceChain)),
		log.FilePath(dir),
	)

	moduleLogger.Debug("Start parsing module")
	p := newModuleParser(moduleLogger, parserOpts{
		StopOnHCLError: r.stopOnHCLError,
		SkipPaths:      r.skipPaths,
	})
	cfg, err := p.parseDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("parse module dir: %w", err)
	}
	moduleLogger.Debug("Module loaded")

	cfg.SourceChain = sourceChain
	return cfg, nil
}

const ManifestSnapshotFile = ".terraform/modules/modules.json"

type ModulesMetadata struct {
	Modules []ModuleMetadata `json:"Modules"`
}

func (m *ModulesMetadata) ModulePath(rootDir string, key string) string {
	for _, module := range m.Modules {
		if module.Key == key {
			return path.Clean(path.Join(rootDir, module.Dir))
		}
	}
	return ""
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
