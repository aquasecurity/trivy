//go:build wasip1

package wasm

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/types"
)

// allocations holds byte slices keyed by their 32-bit pointers (offsets in WASM memory).
// This map ensures that the allocated slices are not garbage-collected as long as we need them.
var allocations = make(map[uint32][]byte)

// allocate creates a byte slice on the Go heap, which resides in WASM linear memory when compiled for WASI.
// It returns a 32-bit pointer (offset) that can be used to access this memory.
func allocate(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	ptr := uint32(uintptr(unsafe.Pointer(&buf[0])))
	allocations[ptr] = buf
	return ptr
}

// malloc exposes a C-style malloc to the host.
// It returns an offset in WASM linear memory where the requested size is allocated.
//
//go:wasmexport malloc
func _malloc(size uint32) uint32 {
	return allocate(size)
}

// free exposes a C-style free to the host.
// It deletes the slice from the allocations map so the memory can be reclaimed by the GC.
//
//go:wasmexport free
func _free(ptr, size uint32) {
	delete(allocations, ptr)
}

// Debug, Info, Warn, Error functions -----------------------------------------

func Debug(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_debug(ptr, size)
}

func Info(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_info(ptr, size)
}

func Warn(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_warn(ptr, size)
}

func Error(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_error(ptr, size)
}

// Imported host functions ---------------------------------------------------

//go:wasmimport env debug
func _debug(ptr, size uint32)

//go:wasmimport env info
func _info(ptr, size uint32)

//go:wasmimport env warn
func _warn(ptr, size uint32)

//go:wasmimport env error
func _error(ptr, size uint32)

var module api.Module

func RegisterModule(p api.Module) {
	module = p
}

// Exported functions --------------------------------------------------------

//go:wasmexport name
func _name() uint64 {
	name := module.Name()
	ptr, size := stringToPtr(name)
	return (uint64(ptr) << 32) | uint64(size)
}

//go:wasmexport api_version
func _apiVersion() uint32 {
	return api.Version
}

//go:wasmexport version
func _version() uint32 {
	return uint32(module.Version())
}

//go:wasmexport is_analyzer
func _isAnalyzer() uint64 {
	if _, ok := module.(api.Analyzer); !ok {
		return 0
	}
	return 1
}

//go:wasmexport required
func _required() uint64 {
	files := module.(api.Analyzer).RequiredFiles()
	return marshal(files)
}

//go:wasmexport analyze
func _analyze(ptr, size uint32) uint64 {
	filePath := ptrToString(ptr, size)
	custom, err := module.(api.Analyzer).Analyze(filePath)
	if err != nil {
		Error(fmt.Sprintf("analyze error: %s", err))
		return 0
	}
	return marshal(custom)
}

//go:wasmexport is_post_scanner
func _isPostScanner() uint64 {
	if _, ok := module.(api.PostScanner); !ok {
		return 0
	}
	return 1
}

//go:wasmexport post_scan_spec
func _post_scan_spec() uint64 {
	return marshal(module.(api.PostScanner).PostScanSpec())
}

//go:wasmexport post_scan
func _post_scan(ptr, size uint32) uint64 {
	var results types.Results
	if err := unmarshal(ptr, size, &results); err != nil {
		Error(fmt.Sprintf("post scan error: %s", err))
		return 0
	}

	results, err := module.(api.PostScanner).PostScan(results)
	if err != nil {
		Error(fmt.Sprintf("post scan error: %s", err))
		return 0
	}
	return marshal(results)
}

// marshal converts the given value to JSON and allocates memory for it in WASM,
// returning a 64-bit packed pointer and size (high 32 bits = pointer, low 32 bits = length).
func marshal(v any) uint64 {
	b, err := json.Marshal(v)
	if err != nil {
		Error(fmt.Sprintf("marshal error: %s", err))
		return 0
	}
	// Allocate space in WASM for the JSON-encoded data
	ptr := allocate(uint32(len(b)))
	// Copy the JSON bytes into the allocated slice
	copy(allocations[ptr], b)

	// Pack the pointer and length into a single uint64
	return (uint64(ptr) << 32) | uint64(len(b))
}

// unmarshal reads the data from WASM memory and unmarshals JSON into v.
func unmarshal(ptr, size uint32, v any) error {
	s := ptrToString(ptr, size)
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}
	return nil
}

// ptrToString constructs a Go string from a pointer and size in WASM memory.
// This uses unsafe.Slice to wrap the memory, then builds a string without an extra copy.
func ptrToString(ptr, size uint32) string {
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size)
	return *(*string)(unsafe.Pointer(&b))
}

// stringToPtr converts a Go string into a pointer and size so that we can return
// them as numeric values in WASM-compatible form.
func stringToPtr(s string) (uint32, uint32) {
	buf := []byte(s)
	p := uintptr(unsafe.Pointer(&buf[0]))
	return uint32(p), uint32(len(buf))
}
