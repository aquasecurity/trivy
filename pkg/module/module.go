package module

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/hashicorp/go-multierror"
	"github.com/liamg/memoryfs"
	"github.com/mailru/easyjson"
	"github.com/samber/lo"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	wasi "github.com/tetratelabs/wazero/wasi_snapshot_preview1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/log"
	tapi "github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/scanner/post"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

var (
	exportFunctions = map[string]interface{}{
		"debug": logDebug,
		"info":  logInfo,
		"warn":  logWarn,
		"error": logError,
	}

	moduleRelativeDir = filepath.Join(".trivy", "modules")
)

func logDebug(ctx context.Context, m api.Module, offset, size uint32) {
	buf := readMemory(ctx, m, offset, size)
	if buf != nil {
		log.Logger.Debug(string(buf))
	}
}

func logInfo(ctx context.Context, m api.Module, offset, size uint32) {
	buf := readMemory(ctx, m, offset, size)
	if buf != nil {
		log.Logger.Info(string(buf))
	}
}

func logWarn(ctx context.Context, m api.Module, offset, size uint32) {
	buf := readMemory(ctx, m, offset, size)
	if buf != nil {
		log.Logger.Warn(string(buf))
	}
}

func logError(ctx context.Context, m api.Module, offset, size uint32) {
	buf := readMemory(ctx, m, offset, size)
	if buf != nil {
		log.Logger.Error(string(buf))
	}
}

func readMemory(ctx context.Context, m api.Module, offset, size uint32) []byte {
	buf, ok := m.Memory().Read(ctx, offset, size)
	if !ok {
		log.Logger.Errorf("Memory.Read(%d, %d) out of range", offset, size)
		return nil
	}
	return buf
}

type Manager struct {
	runtime wazero.Runtime
	modules []*wasmModule
}

func NewManager(ctx context.Context) (*Manager, error) {
	m := &Manager{}

	// Create a new WebAssembly Runtime.
	m.runtime = wazero.NewRuntime()

	// Instantiate a Go-defined module named "env" that exports functions.
	_, err := m.runtime.NewModuleBuilder("env").
		ExportMemoryWithMax("mem", 1, 1).
		ExportFunctions(exportFunctions).
		Instantiate(ctx, m.runtime)
	if err != nil {
		return nil, xerrors.Errorf("wasm module build error: %w", err)
	}

	if _, err = wasi.Instantiate(ctx, m.runtime); err != nil {
		return nil, xerrors.Errorf("WASI init error: %w", err)
	}

	// Load WASM modules in local
	if err = m.loadModules(ctx); err != nil {
		return nil, xerrors.Errorf("module load error: %w", err)
	}

	return m, nil
}

func (m *Manager) loadModules(ctx context.Context) error {
	moduleDir := dir()
	_, err := os.Stat(moduleDir)
	if os.IsNotExist(err) {
		return nil
	}
	log.Logger.Debugf("Module dir: %s", moduleDir)

	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return xerrors.Errorf("read dir error: %w", err)
	}

	for _, entry := range entries {
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".wasm" {
			continue
		}

		fileName := entry.Name()
		filePath := filepath.Join(moduleDir, fileName)

		log.Logger.Infof("Loading %s...", fileName)
		wasmCode, err := os.ReadFile(filePath)
		if err != nil {
			return xerrors.Errorf("file read error: %w", err)
		}

		p, err := newWASMPlugin(ctx, m.runtime, wasmCode)
		if err != nil {
			return xerrors.Errorf("WASM module init error %s: %w", fileName, err)
		}

		m.modules = append(m.modules, p)
	}

	return nil
}

func (m *Manager) Register() {
	for _, mod := range m.modules {
		mod.Register()
	}
}

func (m *Manager) Close(ctx context.Context) error {
	var errs error
	if err := m.runtime.Close(ctx); err != nil {
		errs = multierror.Append(errs, err)
	}
	for _, p := range m.modules {
		if err := p.Close(ctx); err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

func splitPtrSize(u uint64) (uint32, uint32) {
	ptr := uint32(u >> 32)
	size := uint32(u)
	return ptr, size
}

func ptrSizeToString(ctx context.Context, m api.Module, ptrSize uint64) (string, error) {
	ptr, size := splitPtrSize(ptrSize)
	buf := readMemory(ctx, m, ptr, size)
	if buf == nil {
		return "", xerrors.New("unable to read memory")
	}
	return string(buf), nil
}

// stringToPtr returns a pointer and size pair for the given string in a way compatible with WebAssembly numeric types.
func stringToPtrSize(ctx context.Context, s string, mod api.Module, malloc api.Function) (uint64, uint64, error) {
	size := uint64(len(s))
	results, err := malloc.Call(ctx, size)
	if err != nil {
		return 0, 0, xerrors.Errorf("malloc error: %w", err)
	}

	// The pointer is a linear memory offset, which is where we write the string.
	ptr := results[0]
	if !mod.Memory().Write(ctx, uint32(ptr), []byte(s)) {
		return 0, 0, xerrors.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			ptr, size, mod.Memory().Size(ctx))
	}

	return ptr, size, nil
}

func unmarshal(ctx context.Context, m api.Module, ptrSize uint64, v any) error {
	ptr, size := splitPtrSize(ptrSize)
	buf := readMemory(ctx, m, ptr, size)
	if buf == nil {
		return xerrors.New("unable to read memory")
	}
	if err := json.Unmarshal(buf, v); err != nil {
		return xerrors.Errorf("unmarshal error: %w", err)
	}

	return nil
}

func marshal(ctx context.Context, m api.Module, malloc api.Function, v easyjson.Marshaler) (uint64, uint64, error) {
	b, err := easyjson.Marshal(v)
	if err != nil {
		return 0, 0, xerrors.Errorf("marshal error: %w", err)
	}

	size := uint64(len(b))
	results, err := malloc.Call(ctx, size)
	if err != nil {
		return 0, 0, xerrors.Errorf("malloc error: %w", err)
	}

	// The pointer is a linear memory offset, which is where we write the marshaled value.
	ptr := results[0]
	if !m.Memory().Write(ctx, uint32(ptr), b) {
		return 0, 0, xerrors.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			ptr, size, m.Memory().Size(ctx))
	}

	return ptr, size, nil
}

type wasmModule struct {
	mod api.Module

	name          string
	version       int
	requiredFiles []*regexp.Regexp

	isAnalyzer    bool
	isPostScanner bool

	// Exported functions
	analyze  api.Function
	postScan api.Function
	malloc   api.Function // TinyGo specific
	free     api.Function // TinyGo specific
}

func newWASMPlugin(ctx context.Context, r wazero.Runtime, code []byte) (*wasmModule, error) {
	// Combine the above into our baseline config, overriding defaults (which discard stdout and have no file system).
	config := wazero.NewModuleConfig().WithStdout(os.Stdout).WithFS(memoryfs.New())

	// Compile the WebAssembly module using the default configuration.
	compiled, err := r.CompileModule(ctx, code, wazero.NewCompileConfig())
	if err != nil {
		return nil, xerrors.Errorf("module compile error: %w", err)
	}

	// InstantiateModule runs the "_start" function which is what TinyGo compiles "main" to.
	mod, err := r.InstantiateModule(ctx, compiled, config)
	if err != nil {
		return nil, xerrors.Errorf("module init error: %w", err)
	}

	// These are undocumented, but exported. See tinygo-org/tinygo#2788
	// TODO: improve TinyGo specific code
	malloc := mod.ExportedFunction("malloc")
	free := mod.ExportedFunction("free")

	// Get a module name
	name, err := moduleName(ctx, mod)
	if err != nil {
		return nil, xerrors.Errorf("failed to get a module name: %w", err)
	}

	// Get a module version
	version, err := moduleVersion(ctx, mod)
	if err != nil {
		return nil, xerrors.Errorf("failed to get a module version: %w", err)
	}

	// Get a module API version
	apiVersion, err := moduleAPIVersion(ctx, mod)
	if err != nil {
		return nil, xerrors.Errorf("failed to get a module version: %w", err)
	}

	if apiVersion != tapi.Version {
		log.Logger.Infof("Ignore %s@v%d module due to API version mismatch, got: %d, want: %d",
			name, version, apiVersion, tapi.Version)
		return nil, nil
	}

	// Get required files
	requiredFiles, err := moduleRequiredFiles(ctx, mod)
	if err != nil {
		return nil, xerrors.Errorf("failed to get required files: %w", err)
	}

	isAnalyzer, err := moduleIsAnalyzer(ctx, mod)
	if err != nil {
		return nil, xerrors.Errorf("failed to check if the module is an analyzer: %w", err)
	}

	isPostScanner, err := moduleIsPostScanner(ctx, mod)
	if err != nil {
		return nil, xerrors.Errorf("failed to check if the module is a post scanner: %w", err)
	}

	// Get exported functions by WASM module
	analyzeFunc := mod.ExportedFunction("analyze")
	if analyzeFunc == nil {
		return nil, xerrors.New("analyze() must be exported")
	}
	postScanFunc := mod.ExportedFunction("post_scan")
	if postScanFunc == nil {
		return nil, xerrors.New("post_scan() must be exported")
	}

	return &wasmModule{
		mod:           mod,
		name:          name,
		version:       version,
		requiredFiles: requiredFiles,

		isAnalyzer:    isAnalyzer,
		isPostScanner: isPostScanner,

		analyze:  analyzeFunc,
		postScan: postScanFunc,
		malloc:   malloc,
		free:     free,
	}, nil
}

func (m *wasmModule) Register() {
	log.Logger.Infof("Registering WASM module: %s@v%d", m.name, m.version)
	if m.isAnalyzer {
		log.Logger.Debugf("Registering custom analyzer in %s@v%d", m.name, m.version)
		analyzer.RegisterAnalyzer(m)
	}
	if m.isPostScanner {
		log.Logger.Debugf("Registering custom post scanner in %s@v%d", m.name, m.version)
		post.RegisterPostScanner(m)
	}
}

func (m *wasmModule) Close(ctx context.Context) error {
	return m.mod.Close(ctx)
}

func (m *wasmModule) Type() analyzer.Type {
	return analyzer.Type(m.name)
}

func (m *wasmModule) Name() string {
	return m.name
}

func (m *wasmModule) Version() int {
	return m.version
}

func (m *wasmModule) Required(filePath string, _ os.FileInfo) bool {
	for _, r := range m.requiredFiles {
		if r.MatchString(filePath) {
			return true
		}
	}
	return false
}

func (m *wasmModule) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	filePath := "/" + filepath.ToSlash(input.FilePath)
	log.Logger.Debugf("Module %s: analyzing %s...", m.name, filePath)

	memfs := memoryfs.New()
	if err := memfs.MkdirAll(filepath.Dir(filePath), fs.ModePerm); err != nil {
		return nil, xerrors.Errorf("memory fs mkdir error: %w", err)
	}
	err := memfs.WriteLazyFile(filePath, func() (io.Reader, error) {
		return input.Content, nil
	}, fs.ModePerm)
	if err != nil {
		return nil, xerrors.Errorf("memory fs write error: %w", err)
	}

	// Pass memory fs to the analyze() function
	ctx, closer, err := experimental.WithFS(ctx, memfs)
	if err != nil {
		return nil, xerrors.Errorf("fs error: %w", err)
	}
	defer closer.Close(ctx)

	inputPtr, inputSize, err := stringToPtrSize(ctx, filePath, m.mod, m.malloc)
	if err != nil {
		return nil, xerrors.Errorf("failed to write string to memory: %w", err)
	}
	defer m.free.Call(ctx, inputPtr) // nolint: errcheck

	analyzeRes, err := m.analyze.Call(ctx, inputPtr, inputSize)
	if err != nil {
		return nil, xerrors.Errorf("analyze error: %w", err)
	} else if len(analyzeRes) != 1 {
		return nil, xerrors.New("invalid signature: analyze")
	}

	var result analyzer.AnalysisResult
	if err = unmarshal(ctx, m.mod, analyzeRes[0], &result); err != nil {
		return nil, xerrors.Errorf("invalid return value: %w", err)
	}

	return &result, nil
}

// PostScan performs post scanning
// e.g. Remove a vulnerability, change severity, etc.
// TODO: improve memory usage
func (m *wasmModule) PostScan(ctx context.Context, results types.Results) (types.Results, error) {
	serializeResults := lo.Map(results, func(r types.Result, _ int) serialize.Result {
		return serialize.Result(r)
	})

	inputPtr, inputSize, err := marshal(ctx, m.mod, m.malloc, serialize.Results(serializeResults))
	if err != nil {
		return nil, xerrors.Errorf("post scan marshal error: %w", err)
	}
	defer m.free.Call(ctx, inputPtr) //nolint: errcheck

	analyzeRes, err := m.postScan.Call(ctx, inputPtr, inputSize)
	if err != nil {
		return nil, xerrors.Errorf("post scan invocation error: %w", err)
	} else if len(analyzeRes) != 1 {
		return nil, xerrors.New("invalid signature: post_scan")
	}

	if err = unmarshal(ctx, m.mod, analyzeRes[0], &serializeResults); err != nil {
		return nil, xerrors.Errorf("post scan unmarshal error: %w", err)
	}

	// Override scan results
	results = lo.Map(serializeResults, func(r serialize.Result, _ int) types.Result {
		return types.Result(r)
	})

	return results, nil
}

func moduleName(ctx context.Context, mod api.Module) (string, error) {
	nameFunc := mod.ExportedFunction("name")
	if nameFunc == nil {
		return "", xerrors.New("name() must be exported")
	}

	nameRes, err := nameFunc.Call(ctx)
	if err != nil {
		return "", xerrors.Errorf("wasm function name() invocation error: %w", err)
	} else if len(nameRes) != 1 {
		return "", xerrors.New("invalid signature: name()")
	}

	name, err := ptrSizeToString(ctx, mod, nameRes[0])
	if err != nil {
		return "", xerrors.Errorf("invalid return value: %w", err)
	}
	return name, nil
}

func moduleVersion(ctx context.Context, mod api.Module) (int, error) {
	versionFunc := mod.ExportedFunction("version")
	if versionFunc == nil {
		return 0, xerrors.New("version() must be exported")
	}

	versionRes, err := versionFunc.Call(ctx)
	if err != nil {
		return 0, xerrors.Errorf("wasm function version() invocation error: %w", err)
	} else if len(versionRes) != 1 {
		return 0, xerrors.New("invalid signature: version")
	}

	return int(versionRes[0]), nil
}

func moduleAPIVersion(ctx context.Context, mod api.Module) (int, error) {
	versionFunc := mod.ExportedFunction("api_version")
	if versionFunc == nil {
		return 0, xerrors.New("api_version() must be exported")
	}

	versionRes, err := versionFunc.Call(ctx)
	if err != nil {
		return 0, xerrors.Errorf("wasm function api_version() invocation error: %w", err)
	} else if len(versionRes) != 1 {
		return 0, xerrors.New("invalid signature: api_version")
	}

	return int(versionRes[0]), nil
}

func moduleRequiredFiles(ctx context.Context, mod api.Module) ([]*regexp.Regexp, error) {
	requiredFilesFunc := mod.ExportedFunction("required")
	if requiredFilesFunc == nil {
		return nil, xerrors.New("required() must be exported")
	}

	requiredFilesRes, err := requiredFilesFunc.Call(ctx)
	if err != nil {
		return nil, xerrors.Errorf("wasm function required() invocation error: %w", err)
	} else if len(requiredFilesRes) != 1 {
		return nil, xerrors.New("invalid signature: required_files")
	}

	var fileRegexps serialize.StringSlice
	if err = unmarshal(ctx, mod, requiredFilesRes[0], &fileRegexps); err != nil {
		return nil, xerrors.Errorf("invalid return value: %w", err)
	}

	var requiredFiles []*regexp.Regexp
	for _, file := range fileRegexps {
		re, err := regexp.Compile(file)
		if err != nil {
			return nil, xerrors.Errorf("regexp compile error: %w", err)
		}
		requiredFiles = append(requiredFiles, re)
	}

	return requiredFiles, nil
}

func moduleIsAnalyzer(ctx context.Context, mod api.Module) (bool, error) {
	return isType(ctx, mod, "is_analyzer")
}

func moduleIsPostScanner(ctx context.Context, mod api.Module) (bool, error) {
	return isType(ctx, mod, "is_post_scanner")
}

func isType(ctx context.Context, mod api.Module, name string) (bool, error) {
	isFunc := mod.ExportedFunction(name)
	if isFunc == nil {
		return false, xerrors.Errorf("%s() must be exported", name)
	}

	isRes, err := isFunc.Call(ctx)
	if err != nil {
		return false, xerrors.Errorf("wasm function %s() invocation error: %w", name, err)
	} else if len(isRes) != 1 {
		return false, xerrors.Errorf("invalid signature: %s", name)
	}

	return isRes[0] > 0, nil
}

func dir() string {
	return filepath.Join(utils.HomeDir(), moduleRelativeDir)
}
