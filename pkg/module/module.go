package module

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/mailru/easyjson"
	"github.com/samber/lo"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/log"
	tapi "github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/scanner/post"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

var (
	logFunctions = map[string]api.GoModuleFunc{
		"debug": logDebug,
		"info":  logInfo,
		"warn":  logWarn,
		"error": logError,
	}

	RelativeDir = filepath.Join(".trivy", "modules")

	DefaultDir = dir()
)

// logDebug is defined as an api.GoModuleFunc for lower overhead vs reflection.
func logDebug(_ context.Context, mod api.Module, params []uint64) {
	offset, size := uint32(params[0]), uint32(params[1])

	buf := readMemory(mod.Memory(), offset, size)
	if buf != nil {
		log.Logger.Debug(string(buf))
	}

	return
}

// logInfo is defined as an api.GoModuleFunc for lower overhead vs reflection.
func logInfo(_ context.Context, mod api.Module, params []uint64) {
	offset, size := uint32(params[0]), uint32(params[1])

	buf := readMemory(mod.Memory(), offset, size)
	if buf != nil {
		log.Logger.Info(string(buf))
	}

	return
}

// logWarn is defined as an api.GoModuleFunc for lower overhead vs reflection.
func logWarn(_ context.Context, mod api.Module, params []uint64) {
	offset, size := uint32(params[0]), uint32(params[1])

	buf := readMemory(mod.Memory(), offset, size)
	if buf != nil {
		log.Logger.Warn(string(buf))
	}

	return
}

// logError is defined as an api.GoModuleFunc for lower overhead vs reflection.
func logError(_ context.Context, mod api.Module, params []uint64) {
	offset, size := uint32(params[0]), uint32(params[1])

	buf := readMemory(mod.Memory(), offset, size)
	if buf != nil {
		log.Logger.Error(string(buf))
	}

	return
}

func readMemory(mem api.Memory, offset, size uint32) []byte {
	buf, ok := mem.Read(offset, size)
	if !ok {
		log.Logger.Errorf("Memory.Read(%d, %d) out of range", offset, size)
		return nil
	}
	return buf
}

type Options struct {
	Dir            string
	EnabledModules []string
}

type Manager struct {
	cache          wazero.CompilationCache
	modules        []*wasmModule
	dir            string
	enabledModules []string
}

func NewManager(ctx context.Context, opts Options) (*Manager, error) {
	m := &Manager{
		dir:            opts.Dir,
		enabledModules: opts.EnabledModules,
	}

	// Create a new WebAssembly Runtime.
	m.cache = wazero.NewCompilationCache()

	// Load WASM modules in local
	if err := m.loadModules(ctx); err != nil {
		return nil, xerrors.Errorf("module load error: %w", err)
	}

	return m, nil
}

func (m *Manager) loadModules(ctx context.Context) error {
	_, err := os.Stat(m.dir)
	if os.IsNotExist(err) {
		return nil
	}
	log.Logger.Debugf("Module dir: %s", m.dir)

	err = filepath.Walk(m.dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		} else if info.IsDir() || filepath.Ext(info.Name()) != ".wasm" {
			return nil
		}

		rel, err := filepath.Rel(m.dir, path)
		if err != nil {
			return xerrors.Errorf("failed to get a relative path: %w", err)
		}

		log.Logger.Infof("Reading %s...", rel)
		wasmCode, err := os.ReadFile(path)
		if err != nil {
			return xerrors.Errorf("file read error: %w", err)
		}

		p, err := newWASMPlugin(ctx, m.cache, wasmCode)
		if err != nil {
			return xerrors.Errorf("WASM module init error %s: %w", rel, err)
		}

		// Skip Loading WASM modules if not in the list of enable modules flag.
		if len(m.enabledModules) > 0 && !slices.Contains(m.enabledModules, p.Name()) {
			return nil
		}

		log.Logger.Infof("%s loaded", rel)
		m.modules = append(m.modules, p)

		return nil
	})
	if err != nil {
		return xerrors.Errorf("module walk error: %w", err)
	}

	return nil
}

func (m *Manager) Register() {
	for _, mod := range m.modules {
		mod.Register()
	}
}

func (m *Manager) Deregister() {
	for _, mod := range m.modules {
		analyzer.DeregisterAnalyzer(analyzer.Type(mod.Name()))
		post.DeregisterPostScanner(mod.Name())
	}
}

func (m *Manager) Close(ctx context.Context) error {
	return m.cache.Close(ctx)
}

func splitPtrSize(u uint64) (uint32, uint32) {
	ptr := uint32(u >> 32)
	size := uint32(u)
	return ptr, size
}

func ptrSizeToString(mem api.Memory, ptrSize uint64) (string, error) {
	ptr, size := splitPtrSize(ptrSize)
	buf := readMemory(mem, ptr, size)
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
	if !mod.Memory().Write(uint32(ptr), []byte(s)) {
		return 0, 0, xerrors.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			ptr, size, mod.Memory().Size())
	}

	return ptr, size, nil
}

func unmarshal(mem api.Memory, ptrSize uint64, v any) error {
	ptr, size := splitPtrSize(ptrSize)
	buf := readMemory(mem, ptr, size)
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
	if !m.Memory().Write(uint32(ptr), b) {
		return 0, 0, xerrors.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			ptr, size, m.Memory().Size())
	}

	return ptr, size, nil
}

type wasmModule struct {
	mod   api.Module
	memFS *memFS
	mux   sync.Mutex

	name          string
	version       int
	requiredFiles []*regexp.Regexp

	isAnalyzer    bool
	isPostScanner bool
	postScanSpec  serialize.PostScanSpec

	// Exported functions
	analyze  api.Function
	postScan api.Function
	malloc   api.Function // TinyGo specific
	free     api.Function // TinyGo specific
}

func newWASMPlugin(ctx context.Context, ccache wazero.CompilationCache, code []byte) (*wasmModule, error) {
	mf := &memFS{}
	config := wazero.NewModuleConfig().WithStdout(os.Stdout).WithFS(mf)

	// Create an empty namespace so that multiple modules will not conflict
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(ccache))

	// Instantiate a Go-defined module named "env" that exports functions.
	envBuilder := r.NewHostModuleBuilder("env")

	// Avoid reflection for logging as it implies an overhead of >1us per call.
	for n, f := range logFunctions {
		envBuilder.NewFunctionBuilder().
			WithGoModuleFunction(f, []api.ValueType{
				api.ValueTypeI32,
				api.ValueTypeI32,
			}, []api.ValueType{}).
			WithParameterNames("offset", "size").
			Export(n)
	}

	if _, err := envBuilder.Instantiate(ctx); err != nil {
		return nil, xerrors.Errorf("wasm module build error: %w", err)
	}

	if _, err := wasi.NewBuilder(r).Instantiate(ctx); err != nil {
		return nil, xerrors.Errorf("WASI init error: %w", err)
	}

	// Compile the WebAssembly module using the default configuration.
	compiled, err := r.CompileModule(ctx, code)
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

	var requiredFiles []*regexp.Regexp
	if isAnalyzer {
		// Get required files
		requiredFiles, err = moduleRequiredFiles(ctx, mod)
		if err != nil {
			return nil, xerrors.Errorf("failed to get required files: %w", err)
		}
	}

	var postScanSpec serialize.PostScanSpec
	if isPostScanner {
		// This spec defines how the module works in post scanning like INSERT, UPDATE and DELETE.
		postScanSpec, err = modulePostScanSpec(ctx, mod)
		if err != nil {
			return nil, xerrors.Errorf("failed to get a post scan spec: %w", err)
		}
	}

	return &wasmModule{
		mod:           mod,
		memFS:         mf,
		name:          name,
		version:       version,
		requiredFiles: requiredFiles,

		isAnalyzer:    isAnalyzer,
		isPostScanner: isPostScanner,
		postScanSpec:  postScanSpec,

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

	// Wasm module instances are not Goroutine safe, so we take look here since Analyze might be called concurrently.
	// TODO: This is temporary solution and we could improve the Analyze performance by having module instance pool.
	m.mux.Lock()
	defer m.mux.Unlock()

	if err := m.memFS.initialize(filePath, input.Content); err != nil {
		return nil, err
	}

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
	if err = unmarshal(m.mod.Memory(), analyzeRes[0], &result); err != nil {
		return nil, xerrors.Errorf("invalid return value: %w", err)
	}

	return &result, nil
}

// PostScan performs post scanning
// e.g. Remove a vulnerability, change severity, etc.
func (m *wasmModule) PostScan(ctx context.Context, results types.Results) (types.Results, error) {
	// Find custom resources
	var custom serialize.Result
	for _, result := range results {
		if result.Class == types.ClassCustom {
			custom = serialize.Result(result)
			break
		}
	}

	arg := serialize.Results{custom}
	switch m.postScanSpec.Action {
	case tapi.ActionUpdate, tapi.ActionDelete:
		// Pass the relevant results to the module
		arg = append(arg, findIDs(m.postScanSpec.IDs, results)...)
	}

	// Marshal the argument into WASM memory so that the WASM module can read it.
	inputPtr, inputSize, err := marshal(ctx, m.mod, m.malloc, arg)
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

	var got types.Results
	if err = unmarshal(m.mod.Memory(), analyzeRes[0], &got); err != nil {
		return nil, xerrors.Errorf("post scan unmarshal error: %w", err)
	}

	switch m.postScanSpec.Action {
	case tapi.ActionInsert:
		results = append(results, lo.Filter(got, func(r types.Result, _ int) bool {
			return r.Class != types.ClassCustom && r.Class != ""
		})...)
	case tapi.ActionUpdate:
		updateResults(got, results)
	case tapi.ActionDelete:
		deleteResults(got, results)
	}

	return results, nil
}

func findIDs(ids []string, results types.Results) serialize.Results {
	var filtered serialize.Results
	for _, result := range results {
		if result.Class == types.ClassCustom {
			continue
		}
		vulns := lo.Filter(result.Vulnerabilities, func(v types.DetectedVulnerability, _ int) bool {
			return slices.Contains(ids, v.VulnerabilityID)
		})
		misconfs := lo.Filter(result.Misconfigurations, func(m types.DetectedMisconfiguration, _ int) bool {
			return slices.Contains(ids, m.ID)
		})
		if len(vulns) > 0 || len(misconfs) > 0 {
			filtered = append(filtered, serialize.Result{
				Target:            result.Target,
				Class:             result.Class,
				Type:              result.Type,
				Vulnerabilities:   vulns,
				Misconfigurations: misconfs,
			})
		}
	}
	return filtered
}

func updateResults(gotResults, results types.Results) {
	for _, g := range gotResults {
		for i, result := range results {
			if g.Target == result.Target && g.Class == result.Class && g.Type == result.Type {
				results[i].Vulnerabilities = lo.Map(result.Vulnerabilities, func(v types.DetectedVulnerability, _ int) types.DetectedVulnerability {
					// Update vulnerabilities in the existing result
					for _, got := range g.Vulnerabilities {
						if got.VulnerabilityID == v.VulnerabilityID && got.PkgName == v.PkgName &&
							got.PkgPath == v.PkgPath && got.InstalledVersion == v.InstalledVersion {

							// Override vulnerability details
							v.SeveritySource = got.SeveritySource
							v.Vulnerability = got.Vulnerability
						}
					}
					return v
				})

				results[i].Misconfigurations = lo.Map(result.Misconfigurations, func(m types.DetectedMisconfiguration, _ int) types.DetectedMisconfiguration {
					// Update misconfigurations in the existing result
					for _, got := range g.Misconfigurations {
						if got.ID == m.ID &&
							got.CauseMetadata.StartLine == m.CauseMetadata.StartLine &&
							got.CauseMetadata.EndLine == m.CauseMetadata.EndLine {

							// Override misconfiguration details
							m.CauseMetadata = got.CauseMetadata
							m.Severity = got.Severity
							m.Status = got.Status
						}
					}
					return m
				})
			}
		}
	}
}

func deleteResults(gotResults, results types.Results) {
	for _, gotResult := range gotResults {
		for i, result := range results {
			// Remove vulnerabilities and misconfigurations from the existing result
			if gotResult.Target == result.Target && gotResult.Class == result.Class && gotResult.Type == result.Type {
				results[i].Vulnerabilities = lo.Reject(result.Vulnerabilities, func(v types.DetectedVulnerability, _ int) bool {
					for _, got := range gotResult.Vulnerabilities {
						if got.VulnerabilityID == v.VulnerabilityID && got.PkgName == v.PkgName &&
							got.PkgPath == v.PkgPath && got.InstalledVersion == v.InstalledVersion {
							return true
						}
					}
					return false
				})
				results[i].Misconfigurations = lo.Reject(result.Misconfigurations, func(v types.DetectedMisconfiguration, _ int) bool {
					for _, got := range gotResult.Misconfigurations {
						if got.ID == v.ID && got.Status == v.Status &&
							got.CauseMetadata.StartLine == v.CauseMetadata.StartLine &&
							got.CauseMetadata.EndLine == v.CauseMetadata.EndLine {
							return true
						}
					}
					return false
				})
			}
		}
	}
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

	name, err := ptrSizeToString(mod.Memory(), nameRes[0])
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

	return int(uint32(versionRes[0])), nil
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

	return int(uint32(versionRes[0])), nil
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
	if err = unmarshal(mod.Memory(), requiredFilesRes[0], &fileRegexps); err != nil {
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
	return filepath.Join(fsutils.HomeDir(), RelativeDir)
}

func modulePostScanSpec(ctx context.Context, mod api.Module) (serialize.PostScanSpec, error) {
	postScanSpecFunc := mod.ExportedFunction("post_scan_spec")
	if postScanSpecFunc == nil {
		return serialize.PostScanSpec{}, xerrors.New("post_scan_spec() must be exported")
	}

	postScanSpecRes, err := postScanSpecFunc.Call(ctx)
	if err != nil {
		return serialize.PostScanSpec{}, xerrors.Errorf("wasm function post_scan_spec() invocation error: %w", err)
	} else if len(postScanSpecRes) != 1 {
		return serialize.PostScanSpec{}, xerrors.New("invalid signature: post_scan_spec")
	}

	var spec serialize.PostScanSpec
	if err = unmarshal(mod.Memory(), postScanSpecRes[0], &spec); err != nil {
		return serialize.PostScanSpec{}, xerrors.Errorf("invalid return value: %w", err)
	}

	return spec, nil
}
