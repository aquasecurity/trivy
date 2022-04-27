package parser

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tfcontext "github.com/aquasecurity/defsec/parsers/terraform/context"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

type sourceFile struct {
	file *hcl.File
	path string
}

type Parser interface {
	ParseFile(path string) error
	ParseContent(data []byte, fullPath string) error
	ParseDirectory(path string) error
	EvaluateAll() (terraform.Modules, cty.Value, error)
	Metrics() Metrics
	NewModuleParser(modulePath string, moduleName string, moduleBlock *terraform.Block) Parser
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

// Parser is a tool for parsing terraform templates at a given file system location
type parser struct {
	projectRoot    string
	moduleName     string
	modulePath     string
	moduleBlock    *terraform.Block
	files          []sourceFile
	tfvarsPaths    []string
	stopOnHCLError bool
	workspaceName  string
	underlying     *hclparse.Parser
	children       []Parser
	metrics        Metrics
	options        []Option
	debugWriter    io.Writer
	allowDownloads bool
}

// New creates a new Parser
func New(options ...Option) Parser {
	p := &parser{
		workspaceName:  "default",
		underlying:     hclparse.NewParser(),
		options:        options,
		moduleName:     "root",
		debugWriter:    ioutil.Discard,
		allowDownloads: true,
	}

	for _, option := range options {
		option(p)
	}

	return p
}

func (p *parser) debug(format string, args ...interface{}) {
	if p.debugWriter == nil {
		return
	}
	prefix := fmt.Sprintf("[debug:parse][%s] ", p.moduleName)
	_, _ = p.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (p *parser) NewModuleParser(modulePath string, moduleName string, moduleBlock *terraform.Block) Parser {
	mp := New(p.options...)
	mp.(*parser).modulePath = modulePath
	mp.(*parser).moduleBlock = moduleBlock
	mp.(*parser).moduleName = moduleName
	mp.(*parser).projectRoot = p.projectRoot
	p.children = append(p.children, mp)
	return mp
}

func (p *parser) Metrics() Metrics {
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

func (p *parser) ParseContent(data []byte, fullPath string) error {

	if dir := filepath.Dir(fullPath); p.projectRoot == "" || len(dir) < len(p.projectRoot) {
		p.projectRoot = dir
		p.modulePath = dir
	}

	isJSON := strings.HasSuffix(fullPath, ".tf.json")
	isHCL := strings.HasSuffix(fullPath, ".tf")
	if !isJSON && !isHCL {
		return nil
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
	p.debug("Added file %s.", fullPath)
	return nil
}

func (p *parser) ParseFile(fullPath string) error {
	diskStart := time.Now()
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return err
	}
	p.metrics.Timings.DiskIODuration += time.Since(diskStart)
	return p.ParseContent(data, fullPath)
}

// ParseDirectory parses all terraform files within a given directory
func (p *parser) ParseDirectory(fullPath string) error {

	if p.projectRoot == "" {
		p.projectRoot = fullPath
		p.modulePath = fullPath
	}

	fileInfos, err := ioutil.ReadDir(fullPath)
	if err != nil {
		return err
	}

	var paths []string
	for _, info := range fileInfos {
		realPath, info := resolveSymlink(fullPath, info)
		if info.IsDir() {
			continue
		}
		paths = append(paths, realPath)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := p.ParseFile(path); err != nil {
			if p.stopOnHCLError {
				return err
			}
			continue
		}
	}

	p.debug("Added directory %s.", fullPath)
	return nil
}

func (p *parser) EvaluateAll() (terraform.Modules, cty.Value, error) {

	if len(p.files) == 0 {
		p.debug("No files found, nothing to do.")
		return nil, cty.NilVal, nil
	}

	blocks, ignores, err := p.readBlocks(p.files)
	if err != nil {
		return nil, cty.NilVal, err
	}
	p.debug("Read %d block(s) and %d ignore(s) for module '%s' (%d file[s])...", len(blocks), len(ignores), p.moduleName, len(p.files))

	p.metrics.Counts.Blocks = len(blocks)

	var inputVars map[string]cty.Value
	if p.moduleBlock != nil {
		inputVars = p.moduleBlock.Values().AsValueMap()
		p.debug("Added %d input variables from module definition.", len(inputVars))
	} else {
		inputVars, err = loadTFVars(p.tfvarsPaths)
		if err != nil {
			return nil, cty.NilVal, err
		}
		p.debug("Added %d variables from tfvars.", len(inputVars))
	}

	modulesMetadata, err := loadModuleMetadata(p.projectRoot)
	if err != nil {
		p.debug("Error loading module metadata: %s.", err)
	} else {
		p.debug("Loaded module metadata for %d module(s).", len(modulesMetadata.Modules))
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, cty.NilVal, err
	}
	evaluator := newEvaluator(
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
		p.debugWriter,
		p.allowDownloads,
	)
	modules, parseDuration := evaluator.EvaluateAll(context.TODO())
	p.metrics.Counts.Modules = len(modules)
	p.metrics.Timings.ParseDuration = parseDuration
	p.debug("Finished parsing module '%s'.", p.moduleName)
	return modules, evaluator.exportOutputs(), nil
}

func (p *parser) readBlocks(files []sourceFile) (terraform.Blocks, terraform.Ignores, error) {
	var blocks terraform.Blocks
	var ignores terraform.Ignores
	moduleCtx := tfcontext.NewContext(&hcl.EvalContext{}, nil)
	for _, file := range files {
		fileBlocks, fileIgnores, err := loadBlocksFromFile(file)
		if err != nil {
			if p.stopOnHCLError {
				return nil, nil, err
			}
			p.debug("Encountered HCL parse error: %s", err)
			continue
		}
		for _, fileBlock := range fileBlocks {
			blocks = append(blocks, terraform.NewBlock(fileBlock, moduleCtx, p.moduleBlock, nil))
		}
		ignores = append(ignores, fileIgnores...)
	}

	sortBlocksByHierarchy(blocks)
	return blocks, ignores, nil
}

func resolveSymlink(dir string, file os.FileInfo) (string, os.FileInfo) {
	if file.Mode()&os.ModeSymlink != 0 {
		if resolvedLink, err := os.Readlink(filepath.Join(dir, file.Name())); err == nil {
			if info, err := os.Lstat(resolvedLink); err == nil {
				return resolvedLink, info
			}
		}
	}
	return filepath.Join(dir, file.Name()), file
}
