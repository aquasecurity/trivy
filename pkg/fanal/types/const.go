package types

type (
	// TargetType represents the type of target
	TargetType string

	// OSType is an alias of TargetType for operating systems
	OSType = TargetType

	// LangType is an alias of TargetType for programming languages
	LangType = TargetType

	// ConfigType is an alias of TargetType for configuration files
	ConfigType = TargetType
)

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 2
)

// Operating systems
const (
	Alma               OSType = "alma"
	Alpine             OSType = "alpine"
	Amazon             OSType = "amazon"
	Azure              OSType = "azurelinux"
	CBLMariner         OSType = "cbl-mariner"
	CentOS             OSType = "centos"
	Chainguard         OSType = "chainguard"
	Debian             OSType = "debian"
	Fedora             OSType = "fedora"
	OpenSUSE           OSType = "opensuse"
	OpenSUSELeap       OSType = "opensuse-leap"
	OpenSUSETumbleweed OSType = "opensuse-tumbleweed"
	Oracle             OSType = "oracle"
	Photon             OSType = "photon"
	RedHat             OSType = "redhat"
	Rocky              OSType = "rocky"
	SLEMicro           OSType = "slem"
	SLES               OSType = "sles"
	Ubuntu             OSType = "ubuntu"
	Wolfi              OSType = "wolfi"
)

// OSTypeAliases is a map of aliases for operating systems.
// This is used to map the old family names to the new ones for backward compatibility.
var OSTypeAliases = map[OSType]OSType{
	"opensuse.leap":                OpenSUSELeap,
	"opensuse.tumbleweed":          OpenSUSETumbleweed,
	"suse linux enterprise micro":  SLEMicro,
	"suse linux enterprise server": SLES,
}

// Programming language dependencies
const (
	Bundler        LangType = "bundler"
	GemSpec        LangType = "gemspec"
	Cargo          LangType = "cargo"
	Composer       LangType = "composer"
	ComposerVendor LangType = "composer-vendor"
	Npm            LangType = "npm"
	NuGet          LangType = "nuget"
	DotNetCore     LangType = "dotnet-core"
	PackagesProps  LangType = "packages-props"
	Pip            LangType = "pip"
	Pipenv         LangType = "pipenv"
	Poetry         LangType = "poetry"
	Uv             LangType = "uv"
	CondaPkg       LangType = "conda-pkg"
	CondaEnv       LangType = "conda-environment"
	PythonPkg      LangType = "python-pkg"
	NodePkg        LangType = "node-pkg"
	Yarn           LangType = "yarn"
	Pnpm           LangType = "pnpm"
	Jar            LangType = "jar"
	Pom            LangType = "pom"
	Gradle         LangType = "gradle"
	Sbt            LangType = "sbt"
	GoBinary       LangType = "gobinary"
	GoModule       LangType = "gomod"
	JavaScript     LangType = "javascript"
	RustBinary     LangType = "rustbinary"
	Conan          LangType = "conan"
	Cocoapods      LangType = "cocoapods"
	Swift          LangType = "swift"
	Pub            LangType = "pub"
	Hex            LangType = "hex"
	Bitnami        LangType = "bitnami"
	Julia          LangType = "julia"

	K8sUpstream LangType = "kubernetes"
	EKS         LangType = "eks" // Amazon Elastic Kubernetes Service
	GKE         LangType = "gke" // Google Kubernetes Engine
	AKS         LangType = "aks" // Azure Kubernetes Service
	RKE         LangType = "rke" // Rancher Kubernetes Engine
	OCP         LangType = "ocp" // Red Hat OpenShift Container Platform
)

var (
	OSTypes = []OSType{
		Alma,
		Alpine,
		Amazon,
		Azure,
		CBLMariner,
		CentOS,
		Chainguard,
		Debian,
		Fedora,
		OpenSUSE,
		OpenSUSELeap,
		OpenSUSETumbleweed,
		Oracle,
		Photon,
		RedHat,
		Rocky,
		SLEMicro,
		SLES,
		Ubuntu,
		Wolfi,
	}
	AggregatingTypes = []LangType{
		PythonPkg,
		CondaPkg,
		GemSpec,
		NodePkg,
		Jar,
	}
)

// Config files
const (
	JSON                  ConfigType = "json"
	YAML                  ConfigType = "yaml"
	Dockerfile            ConfigType = "dockerfile"
	Terraform             ConfigType = "terraform"
	TerraformPlanJSON     ConfigType = "terraformplan"
	TerraformPlanSnapshot ConfigType = "terraformplan-snapshot"
	CloudFormation        ConfigType = "cloudformation"
	Kubernetes            ConfigType = "kubernetes"
	Helm                  ConfigType = "helm"
	Cloud                 ConfigType = "cloud"
	AzureARM              ConfigType = "azure-arm"
)

// Language-specific file names
const (
	NuGetPkgsLock   = "packages.lock.json"
	NuGetPkgsConfig = "packages.config"

	GoMod = "go.mod"
	GoSum = "go.sum"

	MavenPom = "pom.xml"
	SbtLock  = "build.sbt.lock"

	NpmPkg     = "package.json"
	NpmPkgLock = "package-lock.json"
	YarnLock   = "yarn.lock"
	PnpmLock   = "pnpm-lock.yaml"

	ComposerLock          = "composer.lock"
	ComposerJson          = "composer.json"
	ComposerInstalledJson = "installed.json"

	PyProject       = "pyproject.toml"
	PipRequirements = "requirements.txt"
	PipfileLock     = "Pipfile.lock"
	PoetryLock      = "poetry.lock"
	UvLock          = "uv.lock"

	GemfileLock = "Gemfile.lock"

	CargoLock = "Cargo.lock"
	CargoToml = "Cargo.toml"

	ConanLock = "conan.lock"

	CocoaPodsLock = "Podfile.lock"
	SwiftResolved = "Package.resolved"

	PubSpecLock = "pubspec.lock"

	MixLock = "mix.lock"

	CondaEnvYaml = "environment.yaml"
	CondaEnvYml  = "environment.yml"

	JuliaProject  = "Project.toml"
	JuliaManifest = "Manifest.toml"
)
