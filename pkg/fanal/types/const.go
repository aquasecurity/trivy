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
	CBLMariner         OSType = "cbl-mariner"
	CentOS             OSType = "centos"
	Chainguard         OSType = "chainguard"
	Debian             OSType = "debian"
	Fedora             OSType = "fedora"
	OpenSUSE           OSType = "opensuse"
	OpenSUSELeap       OSType = "opensuse.leap"
	OpenSUSETumbleweed OSType = "opensuse.tumbleweed"
	Oracle             OSType = "oracle"
	Photon             OSType = "photon"
	RedHat             OSType = "redhat"
	Rocky              OSType = "rocky"
	SLES               OSType = "suse linux enterprise server"
	Ubuntu             OSType = "ubuntu"
	Wolfi              OSType = "wolfi"
)

// Programming language dependencies
const (
	Bundler    LangType = "bundler"
	GemSpec    LangType = "gemspec"
	Cargo      LangType = "cargo"
	Composer   LangType = "composer"
	Npm        LangType = "npm"
	NuGet      LangType = "nuget"
	DotNetCore LangType = "dotnet-core"
	Pip        LangType = "pip"
	Pipenv     LangType = "pipenv"
	Poetry     LangType = "poetry"
	CondaPkg   LangType = "conda-pkg"
	PythonPkg  LangType = "python-pkg"
	NodePkg    LangType = "node-pkg"
	Yarn       LangType = "yarn"
	Pnpm       LangType = "pnpm"
	Jar        LangType = "jar"
	Pom        LangType = "pom"
	Gradle     LangType = "gradle"
	GoBinary   LangType = "gobinary"
	GoModule   LangType = "gomod"
	JavaScript LangType = "javascript"
	RustBinary LangType = "rustbinary"
	Conan      LangType = "conan"
	Cocoapods  LangType = "cocoapods"
	Swift      LangType = "swift"
	Pub        LangType = "pub"
	Hex        LangType = "hex"
	Bitnami    LangType = "bitnami"
)

// Config files
const (
	JSON           ConfigType = "json"
	Dockerfile     ConfigType = "dockerfile"
	Terraform      ConfigType = "terraform"
	TerraformPlan  ConfigType = "terraformplan"
	CloudFormation ConfigType = "cloudformation"
	Kubernetes     ConfigType = "kubernetes"
	Helm           ConfigType = "helm"
	Cloud          ConfigType = "cloud"
	AzureARM       ConfigType = "azure-arm"
)

// Language-specific file names
const (
	NuGetPkgsLock   = "packages.lock.json"
	NuGetPkgsConfig = "packages.config"

	GoMod = "go.mod"
	GoSum = "go.sum"

	MavenPom = "pom.xml"

	NpmPkg     = "package.json"
	NpmPkgLock = "package-lock.json"
	YarnLock   = "yarn.lock"
	PnpmLock   = "pnpm-lock.yaml"

	ComposerLock = "composer.lock"
	ComposerJson = "composer.json"

	PyProject       = "pyproject.toml"
	PipRequirements = "requirements.txt"
	PipfileLock     = "Pipfile.lock"
	PoetryLock      = "poetry.lock"

	GemfileLock = "Gemfile.lock"

	CargoLock = "Cargo.lock"
	CargoToml = "Cargo.toml"

	ConanLock = "conan.lock"

	CocoaPodsLock = "Podfile.lock"
	SwiftResolved = "Package.resolved"

	PubSpecLock = "pubspec.lock"

	MixLock = "mix.lock"
)
