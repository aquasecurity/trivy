package parser

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/extrafs"
	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
)

type sourceFile struct {
	file *hcl.File
	path string
}

type Metrics struct {
	Timings struct {
		DiskIODuration time.Duration
		ParseDuration  time.Duration
	}
	Counts struct {
		Blocks          int
		Modules         int
		ModuleDownloads int
		Files           int
	}
}

var _ ConfigurableTerraformParser = (*Parser)(nil)

// Parser is a tool for parsing terraform templates at a given file system location
type Parser struct {
	projectRoot       string
	moduleName        string
	modulePath        string
	moduleSource      string
	moduleFS          fs.FS
	moduleBlock       *terraform.Block
	files             []sourceFile
	tfvarsPaths       []string
	stopOnHCLError    bool
	workspaceName     string
	underlying        *hclparse.Parser
	children          []*Parser
	metrics           Metrics
	options           []options.ParserOption
	debug             debug.Logger
	allowDownloads    bool
	skipCachedModules bool
	fsMap             map[string]fs.FS
	skipRequired      bool
	configsFS         fs.FS
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "terraform", "parser", "<"+p.moduleName+">")
}

func (p *Parser) SetTFVarsPaths(s ...string) {
	p.tfvarsPaths = s
}

func (p *Parser) SetStopOnHCLError(b bool) {
	p.stopOnHCLError = b
}

func (p *Parser) SetWorkspaceName(s string) {
	p.workspaceName = s
}

func (p *Parser) SetAllowDownloads(b bool) {
	p.allowDownloads = b
}

func (p *Parser) SetSkipCachedModules(b bool) {
	p.skipCachedModules = b
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func (p *Parser) SetConfigsFS(fsys fs.FS) {
	p.configsFS = fsys
}

// New creates a new Parser
func New(moduleFS fs.FS, moduleSource string, opts ...options.ParserOption) *Parser {
	p := &Parser{
		workspaceName:  "default",
		underlying:     hclparse.NewParser(),
		options:        opts,
		moduleName:     "root",
		allowDownloads: true,
		moduleFS:       moduleFS,
		moduleSource:   moduleSource,
		configsFS:      moduleFS,
	}

	for _, option := range opts {
		option(p)
	}

	return p
}

func (p *Parser) newModuleParser(moduleFS fs.FS, moduleSource, modulePath, moduleName string, moduleBlock *terraform.Block) *Parser {
	mp := New(moduleFS, moduleSource)
	mp.modulePath = modulePath
	mp.moduleBlock = moduleBlock
	mp.moduleName = moduleName
	mp.projectRoot = p.projectRoot
	p.children = append(p.children, mp)
	for _, option := range p.options {
		option(mp)
	}
	return mp
}

func (p *Parser) Metrics() Metrics {
	total := p.metrics
	for _, child := range p.children {
		metrics := child.Metrics()
		total.Counts.Files += metrics.Counts.Files
		total.Counts.Blocks += metrics.Counts.Blocks
		total.Timings.ParseDuration += metrics.Timings.ParseDuration
		total.Timings.DiskIODuration += metrics.Timings.DiskIODuration
		// NOTE: we don't add module count - this has already propagated to the top level
	}
	return total
}

func (p *Parser) ParseFile(_ context.Context, fullPath string) error {
	diskStart := time.Now()

	isJSON := strings.HasSuffix(fullPath, ".tf.json")
	isHCL := strings.HasSuffix(fullPath, ".tf")
	if !isJSON && !isHCL {
		return nil
	}

	p.debug.Log("Parsing '%s'...", fullPath)
	f, err := p.moduleFS.Open(filepath.ToSlash(fullPath))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	p.metrics.Timings.DiskIODuration += time.Since(diskStart)
	if dir := path.Dir(fullPath); p.projectRoot == "" {
		p.debug.Log("Setting project/module root to '%s'", dir)
		p.projectRoot = dir
		p.modulePath = dir
	}

	start := time.Now()
	var file *hcl.File
	var diag hcl.Diagnostics

	if isHCL {
		file, diag = p.underlying.ParseHCL(data, fullPath)
	} else {
		file, diag = p.underlying.ParseJSON(data, fullPath)
	}
	if diag != nil && diag.HasErrors() {
		return diag
	}
	p.files = append(p.files, sourceFile{
		file: file,
		path: fullPath,
	})
	p.metrics.Counts.Files++
	p.metrics.Timings.ParseDuration += time.Since(start)
	p.debug.Log("Added file %s.", fullPath)
	return nil
}

// ParseFS parses a root module, where it exists at the root of the provided filesystem
func (p *Parser) ParseFS(ctx context.Context, dir string) error {

	dir = path.Clean(dir)

	if p.projectRoot == "" {
		p.debug.Log("Setting project/module root to '%s'", dir)
		p.projectRoot = dir
		p.modulePath = dir
	}

	slashed := filepath.ToSlash(dir)
	p.debug.Log("Parsing FS from '%s'", slashed)
	fileInfos, err := fs.ReadDir(p.moduleFS, slashed)
	if err != nil {
		return err
	}

	var paths []string
	for _, info := range fileInfos {
		realPath := path.Join(dir, info.Name())
		if info.Type()&os.ModeSymlink != 0 {
			extra, ok := p.moduleFS.(extrafs.FS)
			if !ok {
				// we can't handle symlinks in this fs type for now
				p.debug.Log("Cannot resolve symlink '%s' in '%s' for this fs type", info.Name(), dir)
				continue
			}
			realPath, err = extra.ResolveSymlink(info.Name(), dir)
			if err != nil {
				p.debug.Log("Failed to resolve symlink '%s' in '%s': %s", info.Name(), dir, err)
				continue
			}
			info, err := extra.Stat(realPath)
			if err != nil {
				p.debug.Log("Failed to stat resolved symlink '%s': %s", realPath, err)
				continue
			}
			if info.IsDir() {
				continue
			}
			p.debug.Log("Resolved symlink '%s' in '%s' to '%s'", info.Name(), dir, realPath)
		} else if info.IsDir() {
			continue
		}
		paths = append(paths, realPath)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := p.ParseFile(ctx, path); err != nil {
			if p.stopOnHCLError {
				return err
			}
			p.debug.Log("error parsing '%s': %s", path, err)
			continue
		}
	}

	return nil
}

func (p *Parser) EvaluateAll(ctx context.Context) (terraform.Modules, cty.Value, error) {

	p.debug.Log("Evaluating module...")

	if len(p.files) == 0 {
		p.debug.Log("No files found, nothing to do.")
		return nil, cty.NilVal, nil
	}

	blocks, ignores, err := p.readBlocks(p.files)
	if err != nil {
		return nil, cty.NilVal, err
	}
	p.debug.Log("Read %d block(s) and %d ignore(s) for module '%s' (%d file[s])...", len(blocks), len(ignores), p.moduleName, len(p.files))

	p.metrics.Counts.Blocks = len(blocks)

	var inputVars map[string]cty.Value
	if p.moduleBlock != nil {
		inputVars = p.moduleBlock.Values().AsValueMap()
		p.debug.Log("Added %d input variables from module definition.", len(inputVars))
	} else {
		inputVars, err = loadTFVars(p.configsFS, p.tfvarsPaths)
		if err != nil {
			return nil, cty.NilVal, err
		}
		p.debug.Log("Added %d variables from tfvars.", len(inputVars))
	}

	modulesMetadata, metadataPath, err := loadModuleMetadata(p.moduleFS, p.projectRoot)
	if err != nil {
		p.debug.Log("Error loading module metadata: %s.", err)
	} else {
		p.debug.Log("Loaded module metadata for %d module(s) from '%s'.", len(modulesMetadata.Modules), metadataPath)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, cty.NilVal, err
	}
	p.debug.Log("Working directory for module evaluation is '%s'", workingDir)
	evaluator := newEvaluator(
		p.moduleFS,
		p,
		p.projectRoot,
		p.modulePath,
		workingDir,
		p.moduleName,
		blocks,
		inputVars,
		modulesMetadata,
		p.workspaceName,
		ignores,
		p.debug.Extend("evaluator"),
		p.allowDownloads,
		p.skipCachedModules,
	)
	modules, fsMap, parseDuration := evaluator.EvaluateAll(ctx)
	p.metrics.Counts.Modules = len(modules)
	p.metrics.Timings.ParseDuration = parseDuration
	p.debug.Log("Finished parsing module '%s'.", p.moduleName)
	p.fsMap = fsMap
	return modules, evaluator.exportOutputs(), nil
}

func (p *Parser) GetFilesystemMap() map[string]fs.FS {
	if p.fsMap == nil {
		return make(map[string]fs.FS)
	}
	return p.fsMap
}

func (p *Parser) readBlocks(files []sourceFile) (terraform.Blocks, terraform.Ignores, error) {
	var blocks terraform.Blocks
	var ignores terraform.Ignores
	moduleCtx := tfcontext.NewContext(&hcl.EvalContext{}, nil)
	for _, file := range files {
		fileBlocks, fileIgnores, err := loadBlocksFromFile(file, p.moduleSource)
		if err != nil {
			if p.stopOnHCLError {
				return nil, nil, err
			}
			p.debug.Log("Encountered HCL parse error: %s", err)
			continue
		}
		for _, fileBlock := range fileBlocks {
			blocks = append(blocks, terraform.NewBlock(fileBlock, moduleCtx, p.moduleBlock, nil, p.moduleSource, p.moduleFS))
		}
		ignores = append(ignores, fileIgnores...)
	}

	sortBlocksByHierarchy(blocks)
	return blocks, ignores, nil
}
