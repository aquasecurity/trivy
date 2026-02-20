package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

	// Trivy packages should not be imported in Mage (see https://github.com/aquasecurity/trivy/pull/4242),
	// but this package doesn't have so many dependencies, and Mage is still fast.
	//mage:import gittest
	gittest "github.com/aquasecurity/trivy/internal/gittest/testdata"
	//mage:import rpm
	rpm "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/rpm/testdata"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	GOPATH = os.Getenv("GOPATH")
	GOBIN  = filepath.Join(GOPATH, "bin")

	ENV = map[string]string{
		"CGO_ENABLED":  "0",
		"GOEXPERIMENT": "jsonv2",
	}
)

func init() {
	slog.SetDefault(log.New(log.NewHandler(os.Stderr, nil))) // stdout is suppressed in mage
}

func version() (string, error) {
	ver, err := sh.Output("git", "describe", "--tags", "--always")
	if err != nil {
		return "", err
	}
	// Strips the v prefix from the tag
	return strings.TrimPrefix(ver, "v"), nil
}

func buildLdflags() (string, error) {
	ver, err := version()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("-s -w -X=github.com/aquasecurity/trivy/pkg/version/app.ver=%s", ver), nil
}

type Tool mg.Namespace

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
	const version = "v2.10.0"
	bin := filepath.Join(GOBIN, "golangci-lint")
	if exists(bin) && t.matchGolangciLintVersion(bin, version) {
		return nil
	}
	// TODO: use `go install tool`
	// cf. https://golangci-lint.run/welcome/install/#install-from-sources
	command := fmt.Sprintf("curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b %s %s", GOBIN, version)
	return sh.Run("bash", "-c", command)
}

func (Tool) matchGolangciLintVersion(bin, version string) bool {
	out, err := sh.Output(bin, "version", "--json")
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

func (Tool) Install() error {
	log.Info("Installing tools, make sure you add $GOBIN to the $PATH")
	return sh.Run("go", "install", "tool")
}

type Protoc mg.Namespace

// Generate parses PROTO_FILES and generates the Go code for client/server mode
func (Protoc) Generate() error {
	mg.Deps(Tool{}.Install) // Install buf and protoc-gen-twirp

	// Run buf generate
	return sh.RunV("buf", "generate")
}

// Fmt formats protobuf files using buf
func (Protoc) Fmt() error {
	mg.Deps(Tool{}.Install) // Install buf

	// Run buf format
	return sh.RunV("buf", "format", "-w")
}

// Lint runs linting on protobuf files using buf
func (Protoc) Lint() error {
	mg.Deps(Tool{}.Install) // Install buf

	// Run buf lint
	return sh.RunV("buf", "lint")
}

// Breaking checks for breaking changes in protobuf files using buf
func (Protoc) Breaking() error {
	mg.Deps(Tool{}.Install) // Install buf

	// Run buf breaking against main branch
	return sh.RunV("buf", "breaking", "--against", ".git#branch=main")
}

// Yacc generates parser
func Yacc() error {
	mg.Deps(Tool{}.Install) // Install yacc
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
	return compileWasmModules(pattern)
}

// GenerateExampleModules compiles example Wasm modules for integration tests
func (Test) GenerateExampleModules() error {
	pattern := filepath.Join("examples", "module", "*", "*.go")
	return compileWasmModules(pattern)
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
		envs := map[string]string{
			"GOOS":   "wasip1",
			"GOARCH": "wasm",
		}
		if err = sh.RunWith(envs, "go", "generate", src); err != nil {
			return err
		}
	}
	return nil
}

// Unit runs unit tests
func (t Test) Unit() error {
	mg.Deps(t.GenerateModules, rpm.Fixtures, gittest.Fixtures)
	return sh.RunWithV(ENV, "go", "test", "-v", "-short", "-coverprofile=coverage.txt", "-covermode=atomic", "./...")
}

// Integration runs integration tests
func (t Test) Integration() error {
	mg.Deps(t.FixtureContainerImages)
	return sh.RunWithV(ENV, "go", "test", "-timeout", "15m", "-v", "-tags=integration", "./integration/...", "./pkg/fanal/test/integration/...")
}

// K8s runs k8s integration tests
func (t Test) K8s() error {
	mg.Deps(Tool{}.Install) // Install kind
	err := sh.RunWithV(ENV, "kind", "create", "cluster", "--name", "kind-test", "--image", "kindest/node:v1.27.1@sha256:b7d12ed662b873bd8510879c1846e87c7e676a79fefc93e17b2a52989d3ff42b")
	if err != nil {
		return err
	}
	defer func() {
		_ = sh.RunWithV(ENV, "kind", "delete", "cluster", "--name", "kind-test")
	}()
	// wait for the kind cluster is running correctly
	err = sh.RunWithV(ENV, "kubectl", "wait", "--for=condition=Ready", "nodes", "--all", "--timeout=300s")
	if err != nil {
		return fmt.Errorf("can't wait for the kind cluster: %w", err)
	}

	err = sh.RunWithV(ENV, "kubectl", "apply", "-f", "./integration/testdata/fixtures/k8s/test_nginx.yaml")
	if err != nil {
		return fmt.Errorf("can't create a test deployment: %w", err)
	}

	// create an environment for limited user test
	err = initk8sLimitedUserEnv()
	if err != nil {
		return fmt.Errorf("can't create environment for limited user: %w", err)
	}

	// wait for all pods are running correctly
	err = sh.RunWithV(ENV, "kubectl", "wait", "--for=condition=Ready", "pod", "--all", "--all-namespaces", "--timeout=300s")
	if err != nil {
		return fmt.Errorf("can't wait for the pods: %w", err)
	}

	// print all resources for info
	err = sh.RunWithV(ENV, "kubectl", "get", "all", "-A")
	if err != nil {
		return fmt.Errorf("can't get workloads: %w", err)
	}
	err = sh.RunWithV(ENV, "kubectl", "get", "cm", "-A")
	if err != nil {
		return fmt.Errorf("can't get configmaps: %w", err)
	}

	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=k8s_integration", "./integration/...")
}

func initk8sLimitedUserEnv() error {
	commands := [][]string{
		{"kubectl", "create", "namespace", "limitedns"},
		{"kubectl", "create", "-f", "./integration/testdata/fixtures/k8s/limited-pod.yaml"},
		{"kubectl", "create", "serviceaccount", "limiteduser"},
		{"kubectl", "create", "-f", "./integration/testdata/fixtures/k8s/limited-role.yaml"},
		{"kubectl", "create", "-f", "./integration/testdata/fixtures/k8s/limited-binding.yaml"},
		{"cp", "./integration/testdata/fixtures/k8s/kube-config-template", "./integration/limitedconfig"},
	}

	for _, cmd := range commands {
		if err := sh.RunV(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	envs := make(map[string]string)
	var err error
	envs["CA"], err = sh.Output("kubectl", "config", "view", "-o", "jsonpath=\"{.clusters[?(@.name == 'kind-kind-test')].cluster.certificate-authority-data}\"", "--flatten")
	if err != nil {
		return err
	}
	envs["URL"], err = sh.Output("kubectl", "config", "view", "-o", "jsonpath=\"{.clusters[?(@.name == 'kind-kind-test')].cluster.server}\"")
	if err != nil {
		return err
	}
	envs["TOKEN"], err = sh.Output("kubectl", "create", "token", "limiteduser", "--duration=8760h")
	if err != nil {
		return err
	}
	commandsWith := [][]string{
		{"sed", "-i", "-e", "s|{{CA}}|$CA|g", "./integration/limitedconfig"},
		{"sed", "-i", "-e", "s|{{URL}}|$URL|g", "./integration/limitedconfig"},
		{"sed", "-i", "-e", "s|{{TOKEN}}|$TOKEN|g", "./integration/limitedconfig"},
	}
	for _, cmd := range commandsWith {
		if err := sh.RunWithV(envs, cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	return nil
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
	return errors.New("`mage test:updateVMGolden` is currently not supported. See TestVM function comments in integration/vm_test.go for details")
	// mg.Deps(t.FixtureVMImages)
	// return sh.RunWithV(ENV, "go", "test", "-v", "-tags=vm_integration", "./integration/...", "-update")
}

// E2e runs E2E tests using testscript framework
func (t Test) E2e() error {
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=e2e", "./e2e/...")
}

type Lint mg.Namespace

// Run runs linters
func (l Lint) Run() error {
	mg.Deps(Tool{}.GolangciLint, Tool{}.Install)
	return sh.RunWithV(ENV, "golangci-lint", "run", "--build-tags=integration")
}

// Fix auto fixes linters
func (l Lint) Fix() error {
	mg.Deps(Tool{}.GolangciLint, Tool{}.Install)
	return sh.RunWithV(ENV, "golangci-lint", "run", "--fix", "--build-tags=integration")
}

// Fmt formats Go code
func Fmt() error {
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
	mg.Deps(Tool{}.Install) // Install labeler

	args := []string{"apply", "misc/triage/labels.yaml", "-l", "5"}

	// Add --repo flag if GITHUB_REPOSITORY environment variable is set
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		args = append(args, "-r", repo)
	}

	return sh.RunV("labeler", args...)
}

type Docs mg.Namespace

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

type SPDX mg.Namespace

// UpdateLicenseEntries updates both SPDX license IDs and exceptions
func (SPDX) UpdateLicenseEntries() error {
	return sh.RunWith(ENV, "go", "run", "-tags=mage_spdx", "./magefiles/spdx.go")
}
