package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"
)

var (
	GOPATH = os.Getenv("GOPATH")
	GOBIN  = filepath.Join(GOPATH, "bin")

	ENV = map[string]string{
		"CGO_ENABLED": "0",
	}
)

func version() (string, error) {
	if ver, err := sh.Output("git", "describe", "--tags", "--always"); err != nil {
		return "", err
	} else {
		// Strips the v prefix from the tag
		return strings.TrimPrefix(ver, "v"), nil
	}
}

func buildLdflags() (string, error) {
	ver, err := version()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("-s -w -X=github.com/aquasecurity/trivy/pkg/version.ver=%s", ver), nil
}

type Tool mg.Namespace

// Aqua installs aqua if not installed
func (Tool) Aqua() error {
	if exists(filepath.Join(GOBIN, "aqua")) {
		return nil
	}
	return sh.Run("go", "install", "github.com/aquaproj/aqua/v2/cmd/aqua@v2.2.1")
}

// Wire installs wire if not installed
func (Tool) Wire() error {
	if installed("wire") {
		return nil
	}
	return sh.Run("go", "install", "github.com/google/wire/cmd/wire@v0.5.0")
}

// GolangciLint installs golangci-lint
func (Tool) GolangciLint() error {
	const version = "v1.54.2"
	if exists(filepath.Join(GOBIN, "golangci-lint")) {
		return nil
	}
	command := fmt.Sprintf("curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b %s %s", GOBIN, version)
	return sh.Run("bash", "-c", command)
}

// Labeler installs labeler
func (Tool) Labeler() error {
	if exists(filepath.Join(GOBIN, "labeler")) {
		return nil
	}
	return sh.Run("go", "install", "github.com/knqyf263/labeler@latest")
}

// EasyJSON installs easyjson
func (Tool) EasyJSON() error {
	if exists(filepath.Join(GOBIN, "easyjson")) {
		return nil
	}
	return sh.Run("go", "install", "github.com/mailru/easyjson/...@v0.7.7")
}

// Kind installs kind cluster
func (Tool) Kind() error {
	return sh.RunWithV(ENV, "go", "install", "sigs.k8s.io/kind@v0.19.0")
}

// Goyacc installs goyacc
func (Tool) Goyacc() error {
	if exists(filepath.Join(GOBIN, "goyacc")) {
		return nil
	}
	return sh.Run("go", "install", "golang.org/x/tools/cmd/goyacc@v0.7.0")
}

// Mockery installs mockery
func (Tool) Mockery() error {
	if exists(filepath.Join(GOBIN, "mockery")) {
		return nil
	}
	return sh.Run("go", "install", "github.com/knqyf263/mockery/cmd/mockery@latest")
}

// Wire generates the wire_gen.go file for each package
func Wire() error {
	mg.Deps(Tool{}.Wire)
	return sh.RunV("wire", "gen", "./pkg/commands/...", "./pkg/rpc/...")
}

// Mock generates mocks
func Mock(dir string) error {
	mg.Deps(Tool{}.Mockery)
	mockeryArgs := []string{
		"-all",
		"-inpkg",
		"-case=snake",
		"-dir",
		dir,
	}
	return sh.RunV("mockery", mockeryArgs...)
}

// Protoc parses PROTO_FILES and generates the Go code for client/server mode
func Protoc() error {
	// It is called in the protoc container
	if _, ok := os.LookupEnv("TRIVY_PROTOC_CONTAINER"); ok {
		protoFiles, err := findProtoFiles()
		if err != nil {
			return err
		}
		for _, file := range protoFiles {
			// Check if the generated Go file is up-to-date
			dst := strings.TrimSuffix(file, ".proto") + ".pb.go"
			if updated, err := target.Path(dst, file); err != nil {
				return err
			} else if !updated {
				continue
			}

			// Generate
			if err = sh.RunV("protoc", "--twirp_out", ".", "--twirp_opt", "paths=source_relative",
				"--go_out", ".", "--go_opt", "paths=source_relative", file); err != nil {
				return err
			}
		}
		return nil
	}

	// It is called on the host
	if err := sh.RunV("bash", "-c", "docker build -t trivy-protoc - < Dockerfile.protoc"); err != nil {
		return err
	}
	return sh.Run("docker", "run", "--rm", "-it", "--platform", "linux/x86_64", "-v", "${PWD}:/app", "-w", "/app", "trivy-protoc", "mage", "protoc")
}

// Yacc generates parser
func Yacc() error {
	mg.Deps(Tool{}.Goyacc)
	return sh.Run("go", "generate", "./pkg/licensing/expression/...")
}

// Easyjson generates JSON marshaler/unmarshaler for TinyGo/WebAssembly as TinyGo doesn't support encoding/json.
func Easyjson() error {
	mg.Deps(Tool{}.EasyJSON)
	return sh.Run("easyjson", "./pkg/module/serialize/types.go")
}

type Test mg.Namespace

// FixtureContainerImages downloads and extracts required images
func (Test) FixtureContainerImages() error {
	return fixtureContainerImages()
}

// FixtureVMImages downloads and extracts required VM images
func (Test) FixtureVMImages() error {
	return fixtureVMImages()
}

// GenerateModules compiles WASM modules for unit tests
func (Test) GenerateModules() error {
	pattern := filepath.Join("pkg", "module", "testdata", "*", "*.go")
	if err := compileWasmModules(pattern); err != nil {
		return err
	}
	return nil
}

// GenerateExampleModules compiles example Wasm modules for integration tests
func (Test) GenerateExampleModules() error {
	pattern := filepath.Join("examples", "module", "*", "*.go")
	if err := compileWasmModules(pattern); err != nil {
		return err
	}
	return nil
}

// UpdateGolden updates golden files for integration tests
func (Test) UpdateGolden() error {
	return sh.RunWithV(ENV, "go", "test", "-tags=integration", "./integration/...", "./pkg/fanal/test/integration/...", "-update")
}

func compileWasmModules(pattern string) error {
	goFiles, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	for _, src := range goFiles {
		// e.g. examples/module/spring4shell/spring4shell.go
		//   => examples/module/spring4shell/spring4shell.wasm
		dst := strings.TrimSuffix(src, ".go") + ".wasm"
		if updated, err := target.Path(dst, src); err != nil {
			return err
		} else if !updated {
			continue
		}
		// Check if TinyGo is installed
		if !installed("tinygo") {
			return errors.New("need to install TinyGo, follow https://tinygo.org/getting-started/install/")
		}
		if err = sh.Run("go", "generate", src); err != nil {
			return err
		}
	}
	return nil
}

// Unit runs unit tests
func (t Test) Unit() error {
	mg.Deps(t.GenerateModules)
	return sh.RunWithV(ENV, "go", "test", "-v", "-short", "-coverprofile=coverage.txt", "-covermode=atomic", "./...")
}

// Integration runs integration tests
func (t Test) Integration() error {
	mg.Deps(t.FixtureContainerImages)
	return sh.RunWithV(ENV, "go", "test", "-timeout", "15m", "-v", "-tags=integration", "./integration/...", "./pkg/fanal/test/integration/...")
}

// K8s runs k8s integration tests
func (t Test) K8s() error {
	mg.Deps(Tool{}.Kind)

	err := sh.RunWithV(ENV, "kind", "create", "cluster", "--name", "kind-test")
	if err != nil {
		return err
	}
	defer func() {
		_ = sh.RunWithV(ENV, "kind", "delete", "cluster", "--name", "kind-test")
	}()
	err = sh.RunWithV(ENV, "kubectl", "apply", "-f", "./integration/testdata/fixtures/k8s/test_nginx.yaml")
	if err != nil {
		return err
	}
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=k8s_integration", "./integration/...")
}

// Module runs Wasm integration tests
func (t Test) Module() error {
	mg.Deps(t.FixtureContainerImages, t.GenerateExampleModules)
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=module_integration", "./integration/...")
}

// VM runs VM integration tests
func (t Test) VM() error {
	mg.Deps(t.FixtureVMImages)
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=vm_integration", "./integration/...")
}

// UpdateVMGolden updates golden files for integration tests
func (Test) UpdateVMGolden() error {
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=vm_integration", "./integration/...", "-update")
}

type Lint mg.Namespace

// Run runs linters
func (Lint) Run() error {
	mg.Deps(Tool{}.GolangciLint)
	return sh.RunV("golangci-lint", "run", "--timeout", "5m")
}

// Fix auto fixes linters
func (Lint) Fix() error {
	mg.Deps(Tool{}.GolangciLint)
	return sh.RunV("golangci-lint", "run", "--timeout", "5m", "--fix")
}

// Fmt formats Go code and proto files
func Fmt() error {
	// Check if clang-format is installed
	if !installed("clang-format") {
		return errors.New("need to install clang-format")
	}

	// Format proto files
	protoFiles, err := findProtoFiles()
	if err != nil {
		return err
	}
	for _, file := range protoFiles {
		if err = sh.Run("clang-format", "-i", file); err != nil {
			return err
		}
	}

	// Format Go code
	return sh.Run("go", "fmt", "./...")
}

// Tidy makes sure go.mod matches the source code in the module
func Tidy() error {
	return sh.RunV("go", "mod", "tidy")
}

// Build builds Trivy
func Build() error {
	if updated, err := target.Dir("trivy", "pkg", "cmd"); err != nil {
		return err
	} else if !updated {
		return nil
	}

	ldflags, err := buildLdflags()
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	return sh.RunWith(ENV, "go", "build", "-ldflags", ldflags, filepath.Join(wd, "cmd", "trivy"))
}

// Install installs Trivy
func Install() error {
	ldflags, err := buildLdflags()
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	return sh.RunWith(ENV, "go", "install", "-ldflags", ldflags, filepath.Join(wd, "cmd", "trivy"))
}

// Clean cleans up the fixtures
func Clean() error {
	fixtureDir := filepath.Join("integration", "testdata", "fixtures")
	paths := []string{
		filepath.Join(fixtureDir, "images"),
		filepath.Join(fixtureDir, "vm-images"),
	}
	for _, p := range paths {
		if err := sh.Rm(p); err != nil {
			return err
		}
	}
	return nil
}

// Label updates labels
func Label() error {
	mg.Deps(Tool{}.Labeler)
	return sh.RunV("labeler", "apply", "misc/triage/labels.yaml", "-l", "5")
}

type Docs mg.Namespace

// Serve launches MkDocs development server to preview the documentation page
func (Docs) Serve() error {
	const (
		mkdocsImage = "aquasec/mkdocs-material:dev"
		mkdocsPort  = "8000"
	)
	if err := sh.Run("docker", "build", "-t", mkdocsImage, "-f", "docs/build/Dockerfile", "docs/build"); err != nil {
		return err
	}
	return sh.Run("docker", "run", "--name", "mkdocs-serve", "--rm", "-v", "${PWD}:/docs", "-p", mkdocsPort+":8000", mkdocsImage)
}

// Generate generates CLI references
func (Docs) Generate() error {
	return sh.RunWith(ENV, "go", "run", "-tags=mage_docs", "./magefiles")
}

func findProtoFiles() ([]string, error) {
	var files []string
	err := filepath.WalkDir("rpc", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if d.IsDir() {
			return nil
		} else if filepath.Ext(path) == ".proto" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func installed(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
