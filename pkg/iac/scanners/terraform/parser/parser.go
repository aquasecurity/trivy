package parser

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
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
	modulePath        string
	moduleSource      string
	moduleFS          fs.FS
	files             []sourceFile
	tfvarsPaths       []string
	tfvars            map[string]cty.Value
	stopOnHCLError    bool
	workspaceName     string
	underlying        *hclparse.Parser
	baseLogger        *log.Logger // without the module attribute
	logger            *log.Logger
	allowDownloads    bool
	skipCachedModules bool
	fsMap             map[string]fs.FS
	modulesMetadata   map[string]*ModulesMetadata // by filesystem key, nil if modules.json cannot be read
	configsFS         fs.FS
	skipFiles         []string
	skipDirs          []string
	// cwd is optional, if left to empty string, 'os.Getwd'
	// will be used for populating 'path.cwd' in terraform.
	cwd string
}

// New creates a new Parser
func New(moduleFS fs.FS, moduleSource string, opts ...Option) *Parser {
	p := &Parser{
		workspaceName:  "default",
		underlying:     hclparse.NewParser(),
		allowDownloads: true,
		moduleFS:       moduleFS,
		moduleSource:   moduleSource,
		configsFS:      moduleFS,
		logger:         slog.Default(),
		tfvars:         make(map[string]cty.Value),
	}

	for _, option := range opts {
		option(p)
	}

	// Scope the logger to the parser
	p.baseLogger = p.logger.With(log.Prefix("terraform parser"))
	p.logger = p.moduleLogger(rootModuleName)

	return p
}

// moduleLogger returns the logger of the module with the given call name.
func (p *Parser) moduleLogger(name string) *log.Logger {
	return p.baseLogger.With("module", name)
}

func (p *Parser) Files() map[string]*hcl.File {
	return p.underlying.Files()
}

func (p *Parser) ParseFile(_ context.Context, fullPath string) error {
	file, err := parseFile(p.moduleFS, fullPath, p.underlying, p.logger)
	if file == nil {
		return err
	}

	if dir := path.Dir(fullPath); p.projectRoot == "" {
		p.logger.Debug("Setting project/module root", log.FilePath(dir))
		p.projectRoot = dir
		p.modulePath = dir
	}
	p.files = append(p.files, *file)
	return nil
}

// ParseFS parses a root module, where it exists at the root of the provided filesystem
func (p *Parser) ParseFS(_ context.Context, dir string) error {
	if p.moduleFS == nil {
		return errors.New("module filesystem is nil, nothing to parse")
	}
	dir = path.Clean(dir)

	if p.projectRoot == "" {
		p.logger.Debug("Setting project/module root", log.FilePath(dir))
		p.projectRoot = dir
		p.modulePath = dir
	}

	files, err := p.parseDir(p.moduleFS, dir, p.underlying, p.logger)
	p.files = append(p.files, files...)
	return err
}

// parseDir parses the Terraform files of dir in name order.
// A file that fails to parse is logged and skipped, unless stopOnHCLError is set.
func (p *Parser) parseDir(fsys fs.FS, dir string, hclParser *hclparse.Parser, logger *log.Logger) ([]sourceFile, error) {
	dir = path.Clean(dir)
	slashed := filepath.ToSlash(dir)
	logger.Debug("Parsing FS", log.FilePath(slashed))
	fileInfos, err := fs.ReadDir(fsys, slashed)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	skipPaths := utils.CleanSkipPaths(slices.Concat(p.skipFiles, p.skipDirs))

	var paths []string
	for _, info := range fileInfos {
		realPath := path.Join(dir, info.Name())
		if info.IsDir() {
			continue
		}
		if utils.SkipPath(realPath, skipPaths) {
			logger.Debug("Skipping path based on input glob", log.FilePath(realPath), log.Any("glob", skipPaths))
			continue
		}
		paths = append(paths, realPath)
	}
	sort.Strings(paths)

	var files []sourceFile
	for _, path := range paths {
		file, err := parseFile(fsys, path, hclParser, logger)
		if err == nil {
			if file != nil {
				files = append(files, *file)
			}
			continue
		}

		if p.stopOnHCLError {
			return files, err
		}
		if diags, ok := errors.AsType[hcl.Diagnostics](err); ok {
			errc := showParseErrors(logger, fsys, path, diags)
			if errc == nil {
				continue
			}
			logger.Error("Failed to get the causes of the parsing error", log.Err(errc))
		}
		logger.Error("Error parsing file", log.FilePath(path), log.Err(err))
	}

	return files, nil
}

// parseFile parses a Terraform file in HCL or JSON syntax.
// It returns nil for a file of another type.
func parseFile(fsys fs.FS, fullPath string, hclParser *hclparse.Parser, logger *log.Logger) (*sourceFile, error) {
	isJSON := strings.HasSuffix(fullPath, ".tf.json") || strings.HasSuffix(fullPath, ".tofu.json")
	isHCL := strings.HasSuffix(fullPath, ".tf") || strings.HasSuffix(fullPath, ".tofu")
	if !isJSON && !isHCL {
		return nil, nil
	}

	logger.Debug("Parsing", log.FilePath(fullPath))
	f, err := fsys.Open(filepath.ToSlash(fullPath))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var file *hcl.File
	var diag hcl.Diagnostics

	if isHCL {
		file, diag = hclParser.ParseHCL(data, fullPath)
	} else {
		file, diag = hclParser.ParseJSON(data, fullPath)
	}
	if diag != nil && diag.HasErrors() {
		return nil, diag
	}

	logger.Debug("Added file", log.FilePath(fullPath))
	return &sourceFile{file: file, path: fullPath}, nil
}

func showParseErrors(logger *log.Logger, fsys fs.FS, filePath string, diags hcl.Diagnostics) error {
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
			logger.Error("Error parsing file", log.FilePath(filePath),
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

// Load loads the module tree and creates the evaluator of the root module.
func (p *Parser) Load(ctx context.Context) (*evaluator, error) {
	if len(p.files) == 0 {
		p.logger.Info("No files found, nothing to do.")
		return nil, ErrNoFiles
	}

	workingDir, err := p.workingDir()
	if err != nil {
		return nil, err
	}

	inputVars, err := p.rootInputVars()
	if err != nil {
		return nil, err
	}

	root := p.loadModuleTree(ctx, workingDir, inputVars)
	return p.newInstanceEvaluator(root, nil, inputVars, workingDir)
}

// rootInputVars returns the values of the root module variables from the options,
// or from tfvars files and TF_VAR_ environment variables.
func (p *Parser) rootInputVars() (map[string]cty.Value, error) {
	if len(p.tfvars) > 0 {
		return p.tfvars, nil
	}
	return loadTFVars(p.configsFS, p.tfvarsPaths)
}

// workingDir returns the value of path.cwd.
func (p *Parser) workingDir() (string, error) {
	if p.cwd != "" {
		return p.cwd, nil
	}
	return os.Getwd()
}

// newInstanceEvaluator creates the evaluator of one instance of the module.
// moduleBlock is the module block of the instance, or nil for the root module.
func (p *Parser) newInstanceEvaluator(c *moduleConfig, moduleBlock *terraform.Block, inputVars map[string]cty.Value, workingDir string) (*evaluator, error) {
	c.logger.Debug("Loading module", log.String("module", c.name))

	if len(c.files) == 0 {
		c.logger.Info("No files found, nothing to do.")
		return nil, ErrNoFiles
	}

	blocks, ignores, err := p.readBlocks(c, moduleBlock)
	if err != nil {
		return nil, err
	}
	c.logger.Debug("Read block(s) and ignore(s)",
		log.Int("blocks", len(blocks)), log.Int("ignores", len(ignores)))

	c.logger.Debug("Added input variables", log.Int("count", len(inputVars)))
	if moduleBlock == nil && len(p.tfvars) == 0 {
		p.setFallbackValuesForMissingVars(inputVars, blocks)
	}

	c.logger.Debug("Working directory for module evaluation", log.FilePath(workingDir))
	return newEvaluator(p, c, workingDir, blocks, inputVars, ignores,
		c.logger.With(log.Prefix("terraform evaluator"))), nil
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

func (p *Parser) EvaluateAll(ctx context.Context) (terraform.Modules, error) {
	e, err := p.Load(ctx)
	if errors.Is(err, ErrNoFiles) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	modules, fsMap := e.EvaluateAll(ctx)
	p.logger.Debug("Finished parsing module")
	p.fsMap = fsMap
	return modules, nil
}

func (p *Parser) GetFilesystemMap() map[string]fs.FS {
	if p.fsMap == nil {
		return make(map[string]fs.FS)
	}
	return p.fsMap
}

// readBlocks creates the blocks of one module instance from the parsed files.
// moduleBlock is the module block of the instance, or nil for the root module.
func (p *Parser) readBlocks(c *moduleConfig, moduleBlock *terraform.Block) (terraform.Blocks, ignore.Rules, error) {
	var blocks terraform.Blocks
	var ignores ignore.Rules
	moduleCtx := tfcontext.NewContext(&hcl.EvalContext{}, nil)
	for _, file := range c.files {
		fileBlocks, err := loadBlocksFromFile(file)
		if err != nil {
			if p.stopOnHCLError {
				return nil, nil, err
			}
			c.logger.Error("Encountered HCL parse error", log.FilePath(file.path), log.Err(err))
			continue
		}
		for _, fileBlock := range fileBlocks {
			blocks = append(blocks, terraform.NewBlock(fileBlock, moduleCtx, moduleBlock, nil, c.source, c.fsys))
		}
		fileIgnores := ignore.Parse(
			string(file.file.Bytes),
			file.path,
			c.source,
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
	for pair := range strings.SplitSeq(paramStr, ",") {
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
