package parser

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
)

type sourceFile struct {
	file *hcl.File
	path string
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

func (p *Parser) ParseFile(_ context.Context, fullPath string) error {

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

	if dir := path.Dir(fullPath); p.projectRoot == "" {
		p.debug.Log("Setting project/module root to '%s'", dir)
		p.projectRoot = dir
		p.modulePath = dir
	}

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
		if info.IsDir() {
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

var ErrNoFiles = errors.New("no files found")

func (p *Parser) Load(ctx context.Context) (*evaluator, error) {
	p.debug.Log("Evaluating module...")

	if len(p.files) == 0 {
		p.debug.Log("No files found, nothing to do.")
		return nil, ErrNoFiles
	}

	blocks, ignores, err := p.readBlocks(p.files)
	if err != nil {
		return nil, err
	}
	p.debug.Log("Read %d block(s) and %d ignore(s) for module '%s' (%d file[s])...", len(blocks), len(ignores), p.moduleName, len(p.files))

	var inputVars map[string]cty.Value
	if p.moduleBlock != nil {
		inputVars = p.moduleBlock.Values().AsValueMap()
		p.debug.Log("Added %d input variables from module definition.", len(inputVars))
	} else {
		inputVars, err = loadTFVars(p.configsFS, p.tfvarsPaths)
		if err != nil {
			return nil, err
		}
		p.debug.Log("Added %d variables from tfvars.", len(inputVars))
	}

	modulesMetadata, metadataPath, err := loadModuleMetadata(p.moduleFS, p.projectRoot)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		p.debug.Log("Error loading module metadata: %s.", err)
	} else if err == nil {
		p.debug.Log("Loaded module metadata for %d module(s) from %q.", len(modulesMetadata.Modules), metadataPath)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	p.debug.Log("Working directory for module evaluation is %q", workingDir)
	return newEvaluator(
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
	), nil
}

func (p *Parser) EvaluateAll(ctx context.Context) (terraform.Modules, cty.Value, error) {

	e, err := p.Load(ctx)
	if errors.Is(err, ErrNoFiles) {
		return nil, cty.NilVal, nil
	}
	modules, fsMap := e.EvaluateAll(ctx)
	p.debug.Log("Finished parsing module '%s'.", p.moduleName)
	p.fsMap = fsMap
	return modules, e.exportOutputs(), nil
}

func (p *Parser) GetFilesystemMap() map[string]fs.FS {
	if p.fsMap == nil {
		return make(map[string]fs.FS)
	}
	return p.fsMap
}

func (p *Parser) readBlocks(files []sourceFile) (terraform.Blocks, ignore.Rules, error) {
	var blocks terraform.Blocks
	var ignores ignore.Rules
	moduleCtx := tfcontext.NewContext(&hcl.EvalContext{}, nil)
	for _, file := range files {
		fileBlocks, err := loadBlocksFromFile(file)
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
		fileIgnores := ignore.Parse(
			string(file.file.Bytes),
			file.path,
			p.moduleSource,
			&ignore.StringMatchParser{
				SectionKey: "ws",
			},
			&paramParser{},
		)
		ignores = append(ignores, fileIgnores...)
	}

	sortBlocksByHierarchy(blocks)
	return blocks, ignores, nil
}

func loadBlocksFromFile(file sourceFile) (hcl.Blocks, error) {
	contents, diagnostics := file.file.Body.Content(terraform.Schema)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, diagnostics
	}
	if contents == nil {
		return nil, nil
	}
	return contents.Blocks, nil
}

type paramParser struct {
	params map[string]string
}

func (s *paramParser) Key() string {
	return "ignore"
}

func (s *paramParser) Parse(str string) bool {
	s.params = make(map[string]string)

	idx := strings.Index(str, "[")
	if idx == -1 {
		return false
	}

	str = str[idx+1:]

	paramStr := strings.TrimSuffix(str, "]")
	for _, pair := range strings.Split(paramStr, ",") {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			continue
		}
		s.params[parts[0]] = parts[1]
	}
	return true
}

func (s *paramParser) Param() any {
	return s.params
}
