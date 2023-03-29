package analyzer

type Type string

const (
	// ======
	//   OS
	// ======
	TypeOSRelease  Type = "os-release"
	TypeAlpine     Type = "alpine"
	TypeAmazon     Type = "amazon"
	TypeCBLMariner Type = "cbl-mariner"
	TypeDebian     Type = "debian"
	TypePhoton     Type = "photon"
	TypeCentOS     Type = "centos"
	TypeRocky      Type = "rocky"
	TypeAlma       Type = "alma"
	TypeFedora     Type = "fedora"
	TypeOracle     Type = "oracle"
	TypeRedHatBase Type = "redhat"
	TypeSUSE       Type = "suse"
	TypeUbuntu     Type = "ubuntu"
	TypeUbuntuESM  Type = "ubuntu-esm"

	// OS Package
	TypeApk         Type = "apk"
	TypeDpkg        Type = "dpkg"
	TypeDpkgLicense Type = "dpkg-license" // For analyzing licenses
	TypeRpm         Type = "rpm"
	TypeRpmqa       Type = "rpmqa"

	// OS Package Repository
	TypeApkRepo Type = "apk-repo"

	// ============================
	// Programming Language Package
	// ============================

	// Ruby
	TypeBundler Type = "bundler"
	TypeGemSpec Type = "gemspec"

	// Rust
	TypeRustBinary Type = "rustbinary"
	TypeCargo      Type = "cargo"

	// PHP
	TypeComposer Type = "composer"

	// Java
	TypeJar        Type = "jar"
	TypePom        Type = "pom"
	TypeGradleLock Type = "gradle-lockfile"

	// Node.js
	TypeNpmPkgLock Type = "npm"
	TypeNodePkg    Type = "node-pkg"
	TypeYarn       Type = "yarn"
	TypePnpm       Type = "pnpm"

	// .NET
	TypeNuget      Type = "nuget"
	TypeDotNetCore Type = "dotnet-core"

	// Conda
	TypeCondaPkg Type = "conda-pkg"

	// Python
	TypePythonPkg Type = "python-pkg"
	TypePip       Type = "pip"
	TypePipenv    Type = "pipenv"
	TypePoetry    Type = "poetry"

	// Go
	TypeGoBinary Type = "gobinary"
	TypeGoMod    Type = "gomod"

	// C/C++
	TypeConanLock Type = "conan-lock"

	// Elixir
	TypeMixLock Type = "mix-lock"

	// Swift
	TypeCocoaPods Type = "cocoapods"

	// Dart
	TypePubSpecLock Type = "pubspec-lock"

	// ============
	// Non-packaged
	// ============
	TypeExecutable Type = "executable"

	// ============
	// Image Config
	// ============
	TypeApkCommand        Type = "apk-command"
	TypeHistoryDockerfile Type = "history-dockerfile"
	TypeImageConfigSecret Type = "image-config-secret"

	// =================
	// Structured Config
	// =================
	TypeYaml           Type = "yaml"
	TypeJSON           Type = "json"
	TypeDockerfile     Type = "dockerfile"
	TypeTerraform      Type = "terraform"
	TypeCloudFormation Type = "cloudFormation"
	TypeHelm           Type = "helm"

	// ========
	// License
	// ========
	TypeLicenseFile Type = "license-file"

	// ========
	// Secrets
	// ========
	TypeSecret Type = "secret"

	// =======
	// Red Hat
	// =======
	TypeRedHatContentManifestType Type = "redhat-content-manifest"
	TypeRedHatDockerfileType      Type = "redhat-dockerfile"
)

var (
	// TypeOSes has all OS-related analyzers
	TypeOSes = []Type{
		TypeOSRelease,
		TypeAlpine,
		TypeAmazon,
		TypeCBLMariner,
		TypeDebian,
		TypePhoton,
		TypeCentOS,
		TypeRocky,
		TypeAlma,
		TypeFedora,
		TypeOracle,
		TypeRedHatBase,
		TypeSUSE,
		TypeUbuntu,
		TypeApk,
		TypeDpkg,
		TypeDpkgLicense,
		TypeRpm,
		TypeRpmqa,
		TypeApkRepo,
	}

	// TypeLanguages has all language analyzers
	TypeLanguages = []Type{
		TypeBundler,
		TypeGemSpec,
		TypeCargo,
		TypeComposer,
		TypeJar,
		TypePom,
		TypeGradleLock,
		TypeNpmPkgLock,
		TypeNodePkg,
		TypeYarn,
		TypePnpm,
		TypeNuget,
		TypeDotNetCore,
		TypeCondaPkg,
		TypePythonPkg,
		TypePip,
		TypePipenv,
		TypePoetry,
		TypeGoBinary,
		TypeGoMod,
		TypeRustBinary,
		TypeConanLock,
		TypeCocoaPods,
		TypePubSpecLock,
		TypeMixLock,
	}

	// TypeLockfiles has all lock file analyzers
	TypeLockfiles = []Type{
		TypeBundler,
		TypeNpmPkgLock,
		TypeYarn,
		TypePnpm,
		TypePip,
		TypePipenv,
		TypePoetry,
		TypeGoMod,
		TypePom,
		TypeConanLock,
		TypeGradleLock,
		TypeCocoaPods,
		TypePubSpecLock,
		TypeMixLock,
	}

	// TypeIndividualPkgs has all analyzers for individual packages
	TypeIndividualPkgs = []Type{
		TypeGemSpec,
		TypeNodePkg,
		TypeCondaPkg,
		TypePythonPkg,
		TypeGoBinary,
		TypeJar,
		TypeRustBinary,
	}

	// TypeConfigFiles has all config file analyzers
	TypeConfigFiles = []Type{
		TypeYaml,
		TypeJSON,
		TypeDockerfile,
		TypeTerraform,
		TypeCloudFormation,
		TypeHelm,
	}
)
