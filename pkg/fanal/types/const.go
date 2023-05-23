package types

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 2
)

const (
	// Programming language dependencies
	Bundler    = "bundler"
	GemSpec    = "gemspec"
	Cargo      = "cargo"
	Composer   = "composer"
	Npm        = "npm"
	NuGet      = "nuget"
	DotNetCore = "dotnet-core"
	Pip        = "pip"
	Pipenv     = "pipenv"
	Poetry     = "poetry"
	CondaPkg   = "conda-pkg"
	PythonPkg  = "python-pkg"
	NodePkg    = "node-pkg"
	Yarn       = "yarn"
	Pnpm       = "pnpm"
	Jar        = "jar"
	Pom        = "pom"
	Gradle     = "gradle"
	GoBinary   = "gobinary"
	GoModule   = "gomod"
	JavaScript = "javascript"
	RustBinary = "rustbinary"
	Conan      = "conan"
	Cocoapods  = "cocoapods"
	Pub        = "pub"
	Hex        = "hex"

	// Config files
	YAML           = "yaml"
	JSON           = "json"
	Dockerfile     = "dockerfile"
	Terraform      = "terraform"
	CloudFormation = "cloudformation"
	Kubernetes     = "kubernetes"
	Ansible        = "ansible"
	Helm           = "helm"
	Cloud          = "cloud"
	AzureARM       = "azure-arm"

	// Licensing
	License = "license"

	// Language-specific file names
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

	PubSpecLock = "pubspec.lock"

	MixLock = "mix.lock"
)
