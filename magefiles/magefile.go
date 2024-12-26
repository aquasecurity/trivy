package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

	//mage:import rpm
	rpm "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/rpm/testdata"
	// Trivy packages should not be imported in Mage (see https://github.com/aquasecurity/trivy/pull/4242),
	// but this package doesn't have so many dependencies, and Mage is still fast.
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	GOPATH = os.Getenv("GOPATH")
	GOBIN  = filepath.Join(GOPATH, "bin")

	ENV = map[string]string{
		"CGO_ENABLED": "0",
	}
)

var protoFiles = []string{
	"pkg/iac/scanners/terraformplan/snapshot/planproto/planfile.proto",
}

func init() {
	slog.SetDefault(log.New(log.NewHandler(os.Stderr, nil))) // stdout is suppressed in mage
}

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
	return fmt.Sprintf("-s -w -X=github.com/aquasecurity/trivy/pkg/version/app.ver=%s", ver), nil
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

// Sass installs saas if not installed. npm is assumed to be available
func (Tool) Sass() error {
	if installed("sass") {
		return nil
	}
	return sh.Run("npm", "install", "-g", "saas")
}

// PipTools installs PipTools if not installed. python is assumed to be available and relevant environment to have been activated
func (Tool) PipTools() error {
	if installed("pip-compile") {
		return nil
	}
	return sh.Run("python", "-m", "pip", "install", "pip-tools")
}

// GolangciLint installs golangci-lint
func (t Tool) GolangciLint() error {
	const version = "v1.61.0"
	bin := filepath.Join(GOBIN, "golangci-lint")
	if exists(bin) && t.matchGolangciLintVersion(bin, version) {
		return nil
	}
	command := fmt.Sprintf("curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b %s %s", GOBIN, version)
	return sh.Run("bash", "-c", command)
}

func (Tool) matchGolangciLintVersion(bin, version string) bool {
	out, err := sh.Output(bin, "version", "--format", "json")
	if err != nil {
		slog.Error("Unable to get golangci-lint version", slog.Any("err", err))
		return false
	}
	var output struct {
		Version string `json:"Version"`
	}
	if err = json.Unmarshal([]byte(out), &output); err != nil {
		slog.Error("Unable to parse golangci-lint version", slog.Any("err", err))
		return false
	}

	version = strings.TrimPrefix(version, "v")
	if output.Version != version {
		slog.Info("golangci-lint version mismatch", slog.String("expected", version), slog.String("actual", output.Version))
		return false
	}
	return true
}

// Labeler installs labeler
func (Tool) Labeler() error {
	if exists(filepath.Join(GOBIN, "labeler")) {
		return nil
	}
	return sh.Run("go", "install", "github.com/knqyf263/labeler@latest")
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
	return sh.RunV("wire", "gen", "./pkg/commands/...", "./pkg/rpc/...", "./pkg/k8s/...")
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
		rpcProtoFiles, err := findRPCProtoFiles()
		if err != nil {
			return err
		}
		for _, file := range rpcProtoFiles {
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

		for _, file := range protoFiles {
			if err := sh.RunV("protoc", ".", "paths=source_relative", "--go_out", ".", "--go_opt",
				"paths=source_relative", file); err != nil {
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

type Test mg.Namespace

// FixtureContainerImages downloads and extracts required images
func (Test) FixtureContainerImages() error {
	return fixtureContainerImages()
}

// FixtureVMImages downloads and extracts required VM images
func (Test) FixtureVMImages() error {
	return fixtureVMImages()
}

// FixtureTerraformPlanSnapshots generates Terraform Plan files in test folders
func (Test) FixtureTerraformPlanSnapshots() error {
	return fixtureTerraformPlanSnapshots(context.TODO())
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
	mg.Deps(t.GenerateModules, rpm.Fixtures)
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

// UpdateModuleGolden updates golden files for Wasm integration tests
func (t Test) UpdateModuleGolden() error {
	mg.Deps(t.FixtureContainerImages, t.GenerateExampleModules)
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=module_integration", "./integration/...", "-update")
}

// VM runs VM integration tests
func (t Test) VM() error {
	mg.Deps(t.FixtureVMImages)
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=vm_integration", "./integration/...")
}

// UpdateVMGolden updates golden files for integration tests
func (t Test) UpdateVMGolden() error {
	mg.Deps(t.FixtureVMImages)
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=vm_integration", "./integration/...", "-update")
}

type Lint mg.Namespace

// Run runs linters
func (Lint) Run() error {
	mg.Deps(Tool{}.GolangciLint)
	return sh.RunV("golangci-lint", "run")
}

// Fix auto fixes linters
func (Lint) Fix() error {
	mg.Deps(Tool{}.GolangciLint)
	return sh.RunV("golangci-lint", "run", "--fix")
}

// Fmt formats Go code and proto files
func Fmt() error {
	// Check if clang-format is installed
	if !installed("clang-format") {
		return errors.New("need to install clang-format")
	}

	// Format proto files
	rpcProtoFiles, err := findRPCProtoFiles()
	if err != nil {
		return err
	}

	allProtoFiles := append(protoFiles, rpcProtoFiles...)
	for _, file := range allProtoFiles {
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

// Prepare CSS
func (Docs) Css() error {
	const (
		homepageSass = "docs/assets/css/trivy_v1_homepage.scss"
	)
	homepageCss := strings.TrimSuffix(homepageSass, ".scss") + ".min.css"
	if updated, err := target.Path(homepageCss, homepageSass); err != nil {
		return err
	} else if !updated {
		return nil
	}
	return sh.Run("sass", "--no-source-map", "--style=compressed", homepageSass, homepageCss)
}

// Prepare python requirements
func (Docs) Pip() error {
	const (
		requirementsIn = "docs/build/requirements.in"
	)
	requirementsTxt := strings.TrimSuffix(requirementsIn, ".in") + ".txt"
	if updated, err := target.Path(requirementsTxt, requirementsIn); err != nil {
		return err
	} else if !updated {
		return nil
	}
	return sh.Run("pip-compile", requirementsIn, "--output-file", requirementsTxt)
}

// Serve launches MkDocs development server to preview the documentation page
func (Docs) Serve() error {
	const (
		mkdocsImage = "trivy-docs:dev"
		mkdocsPort  = "8000"
	)
	if err := sh.Run("docker", "build", "-t", mkdocsImage, "docs/build"); err != nil {
		return err
	}
	return sh.Run("docker", "run", "--name", "mkdocs-serve", "--rm", "-v", "${PWD}:/docs", "-p", mkdocsPort+":8000", mkdocsImage)
}

// Generate generates CLI references
func (Docs) Generate() error {
	return sh.RunWith(ENV, "go", "run", "-tags=mage_docs", "./magefiles")
}

func findRPCProtoFiles() ([]string, error) {
	var files []string
	err := filepath.WalkDir("rpc", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case filepath.Ext(path) == ".proto":
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

type Schema mg.Namespace

// Generate generates Cloud Schema for misconfiguration scanning
func (Schema) Generate() error {
	return sh.RunWith(ENV, "go", "run", "-tags=mage_schema", "./magefiles", "--", "generate")
}

// Verify verifies Cloud Schema for misconfiguration scanning
func (Schema) Verify() error {
	return sh.RunWith(ENV, "go", "run", "-tags=mage_schema", "./magefiles", "--", "verify")
}

// VEX generates a VEX document for Trivy
func VEX(_ context.Context, dir string) error {
	return sh.RunWith(ENV, "go", "run", "-tags=mage_vex", "./magefiles/vex.go", "--dir", dir)
}

type Helm mg.Namespace

// UpdateVersion updates a version for Trivy Helm Chart and creates a PR
func (Helm) UpdateVersion() error {
	return sh.RunWith(ENV, "go", "run", "-tags=mage_helm", "./magefiles")
}
