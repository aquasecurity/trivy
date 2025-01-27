package parser

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/log"
)

type sourceFile struct {
	file *hcl.File
	path string
}

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
	tfvars            map[string]cty.Value
	stopOnHCLError    bool
	workspaceName     string
	underlying        *hclparse.Parser
	children          []*Parser
	options           []Option
	logger            *log.Logger
	allowDownloads    bool
	skipCachedModules bool
	fsMap             map[string]fs.FS
	configsFS         fs.FS
	skipPaths         []string
	stepHooks         []EvaluateStepHook
}

// New creates a new Parser
func New(moduleFS fs.FS, moduleSource string, opts ...Option) *Parser {
	p := &Parser{
		workspaceName:  "default",
		underlying:     hclparse.NewParser(),
		options:        opts,
		moduleName:     "root",
		allowDownloads: true,
		moduleFS:       moduleFS,
		moduleSource:   moduleSource,
		configsFS:      moduleFS,
		logger:         log.WithPrefix("terraform parser").With("module", "root"),
		tfvars:         make(map[string]cty.Value),
		stepHooks:      make([]EvaluateStepHook, 0),
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
	mp.logger = log.WithPrefix("terraform parser").With("module", moduleName)
	mp.projectRoot = p.projectRoot
	mp.skipPaths = p.skipPaths
	mp.options = p.options
	p.children = append(p.children, mp)
	for _, option := range p.options {
		option(mp)
	}
	return mp
}

func (p *Parser) Files() map[string]*hcl.File {
	return p.underlying.Files()
}

func (p *Parser) ParseFile(_ context.Context, fullPath string) error {

	isJSON := strings.HasSuffix(fullPath, ".tf.json")
	isHCL := strings.HasSuffix(fullPath, ".tf")
	if !isJSON && !isHCL {
		return nil
	}

	p.logger.Debug("Parsing", log.FilePath(fullPath))
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
		p.logger.Debug("Setting project/module root", log.FilePath(dir))
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

	p.logger.Debug("Added file", log.FilePath(fullPath))
	return nil
}

// ParseFS parses a root module, where it exists at the root of the provided filesystem
func (p *Parser) ParseFS(ctx context.Context, dir string) error {

	dir = path.Clean(dir)

	if p.projectRoot == "" {
		p.logger.Debug("Setting project/module root", log.FilePath(dir))
		p.projectRoot = dir
		p.modulePath = dir
	}

	slashed := filepath.ToSlash(dir)
	p.logger.Debug("Parsing FS", log.FilePath(slashed))
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
		if utils.SkipPath(realPath, utils.CleanSkipPaths(p.skipPaths)) {
			p.logger.Debug("Skipping path based on input glob", log.FilePath(realPath), log.Any("glob", p.skipPaths))
			continue
		}
		paths = append(paths, realPath)
	}
	sort.Strings(paths)
	for _, path := range paths {
		var err error
		if err = p.ParseFile(ctx, path); err == nil {
			continue
		}

		if p.stopOnHCLError {
			return err
		}
		var diags hcl.Diagnostics
		if errors.As(err, &diags) {
			errc := p.showParseErrors(p.moduleFS, path, diags)
			if errc == nil {
				continue
			}
			p.logger.Error("Failed to get the causes of the parsing error", log.Err(errc))
		}
		p.logger.Error("Error parsing file", log.FilePath(path), log.Err(err))
		continue
	}

	return nil
}

func (p *Parser) showParseErrors(fsys fs.FS, filePath string, diags hcl.Diagnostics) error {
	file, err := fsys.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	defer file.Close()

	for _, diag := range diags {
		if subj := diag.Subject; subj != nil {
			lines, err := readLinesFromFile(file, subj.Start.Line, subj.End.Line)
			if err != nil {
				return err
			}

			cause := strings.Join(lines, "\n")
			p.logger.Error("Error parsing file", log.FilePath(filePath),
				log.String("cause", cause), log.Err(diag))
		}
	}

	return nil
}

func readLinesFromFile(f io.Reader, from, to int) ([]string, error) {
	scanner := bufio.NewScanner(f)
	rawLines := make([]string, 0, to-from+1)

	for lineNum := 0; scanner.Scan() && lineNum < to; lineNum++ {
		if lineNum >= from-1 {
			rawLines = append(rawLines, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan file: %w", err)
	}

	return rawLines, nil
}

var ErrNoFiles = errors.New("no files found")

func (p *Parser) Load(ctx context.Context) (*evaluator, error) {
	p.logger.Debug("Loading module", log.String("module", p.moduleName))

	if len(p.files) == 0 {
		p.logger.Info("No files found, nothing to do.")
		return nil, ErrNoFiles
	}

	blocks, ignores, err := p.readBlocks(p.files)
	if err != nil {
		return nil, err
	}
	p.logger.Debug("Read block(s) and ignore(s)",
		log.Int("blocks", len(blocks)), log.Int("ignores", len(ignores)))

	var inputVars map[string]cty.Value

	switch {
	case p.moduleBlock != nil:
		inputVars = p.moduleBlock.Values().AsValueMap()
		p.logger.Debug("Added input variables from module definition",
			log.Int("count", len(inputVars)))
	case len(p.tfvars) > 0:
		inputVars = p.tfvars
		p.logger.Debug("Added input variables from tfvars.", log.Int("count", len(inputVars)))
	default:
		inputVars, err = loadTFVars(p.configsFS, p.tfvarsPaths)
		if err != nil {
			return nil, err
		}
		p.logger.Debug("Added input variables from tfvars", log.Int("count", len(inputVars)))
		p.setFallbackValuesForMissingVars(inputVars, blocks)
	}

	modulesMetadata, metadataPath, err := loadModuleMetadata(p.moduleFS, p.projectRoot)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		p.logger.Error("Error loading module metadata", log.Err(err))
	} else if err == nil {
		p.logger.Debug("Loaded module metadata for modules",
			log.FilePath(metadataPath),
			log.Int("count", len(modulesMetadata.Modules)),
		)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	p.logger.Debug("Working directory for module evaluation", log.FilePath(workingDir))
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
		log.WithPrefix("terraform evaluator"),
		p.allowDownloads,
		p.skipCachedModules,
		p.stepHooks,
	), nil
}

func missingVariableValues(blocks terraform.Blocks, inputVars map[string]cty.Value) []*terraform.Block {
	var missing []*terraform.Block
	for _, varBlock := range blocks.OfType("variable") {
		if varBlock.GetAttribute("default") == nil {
			if _, ok := inputVars[varBlock.TypeLabel()]; !ok {
				missing = append(missing, varBlock)
			}
		}
	}

	return missing
}

// Set fallback values for missing variables, to allow expressions using them to be
// still be possibly evaluated to a value different than null.
func (p *Parser) setFallbackValuesForMissingVars(inputVars map[string]cty.Value, blocks []*terraform.Block) {
	varBlocks := missingVariableValues(blocks, inputVars)
	if len(varBlocks) == 0 {
		return
	}

	missingVars := make([]string, 0, len(varBlocks))
	for _, block := range varBlocks {
		varType := inputVariableType(block)
		if varType != cty.NilType {
			inputVars[block.TypeLabel()] = cty.UnknownVal(varType)
		} else {
			inputVars[block.TypeLabel()] = cty.DynamicVal
		}
		missingVars = append(missingVars, block.TypeLabel())
	}

	p.logger.Warn(
		"Variable values were not found in the environment or variable files. Evaluating may not work correctly.",
		log.String("variables", strings.Join(missingVars, ", ")),
	)
}

func inputVariableType(b *terraform.Block) cty.Type {
	typeAttr, exists := b.Attributes()["type"]
	if !exists {
		return cty.NilType
	}
	ty, _, err := typeAttr.DecodeVarType()
	if err != nil {
		return cty.NilType
	}
	return ty
}

func (p *Parser) EvaluateAll(ctx context.Context) (terraform.Modules, cty.Value, error) {

	e, err := p.Load(ctx)
	if errors.Is(err, ErrNoFiles) {
		return nil, cty.NilVal, nil
	} else if err != nil {
		return nil, cty.NilVal, err
	}

	modules, fsMap := e.EvaluateAll(ctx)
	p.logger.Debug("Finished parsing module")
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
			p.logger.Error("Encountered HCL parse error", log.FilePath(file.path), log.Err(err))
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
