package analyzer

import (
	"github.com/aquasecurity/trivy/pkg/iac/detection"
)

type Type string

const (
	// ======
	//   OS
	// ======
	TypeOSRelease  Type = "os-release"
	TypeAlpine     Type = "alpine"
	TypeAmazon     Type = "amazon"
	TypeAzure      Type = "azurelinux"
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
	TypeApk          Type = "apk"
	TypeBottlerocket Type = "bottlerocket"
	TypeDpkg         Type = "dpkg"
	TypeDpkgLicense  Type = "dpkg-license" // For analyzing licenses
	TypeRpm          Type = "rpm"
	TypeRpmArchive   Type = "rpm-archive"
	TypeRpmqa        Type = "rpmqa"

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
	TypeComposer       Type = "composer"
	TypeComposerVendor Type = "composer-vendor"

	// Java
	TypeJar        Type = "jar"
	TypePom        Type = "pom"
	TypeGradleLock Type = "gradle-lockfile"
	TypeSbtLock    Type = "sbt-lockfile"

	// Node.js
	TypeNpmPkgLock Type = "npm"
	TypeNodePkg    Type = "node-pkg"
	TypeYarn       Type = "yarn"
	TypePnpm       Type = "pnpm"

	// .NET
	TypeNuget         Type = "nuget"
	TypeDotNetCore    Type = "dotnet-core"
	TypePackagesProps Type = "packages-props"

	// Conda
	TypeCondaPkg Type = "conda-pkg"
	TypeCondaEnv Type = "conda-environment"

	// Python
	TypePythonPkg    Type = "python-pkg"
	TypePythonPkgEgg Type = "python-egg"
	TypePip          Type = "pip"
	TypePipenv       Type = "pipenv"
	TypePoetry       Type = "poetry"
	TypeUv           Type = "uv"

	// Go
	TypeGoBinary Type = "gobinary"
	TypeGoMod    Type = "gomod"

	// C/C++
	TypeConanLock Type = "conan-lock"

	// Elixir
	TypeMixLock Type = "mix-lock"

	// Swift
	TypeSwift     Type = "swift"
	TypeCocoaPods Type = "cocoapods"

	// Dart
	TypePubSpecLock Type = "pubspec-lock"

	// Julia
	TypeJulia Type = "julia"

	// ============
	// Non-packaged
	// ============
	TypeExecutable Type = "executable"
	TypeSBOM       Type = "sbom"

	// ============
	// Image Config
	// ============
	TypeApkCommand        Type = "apk-command"
	TypeHistoryDockerfile Type = "history-dockerfile"
	TypeImageConfigSecret Type = "image-config-secret"

	// =================
	// Structured Config
	// =================
	TypeAzureARM              Type = Type(detection.FileTypeAzureARM)
	TypeCloudFormation        Type = Type(detection.FileTypeCloudFormation)
	TypeDockerfile            Type = Type(detection.FileTypeDockerfile)
	TypeHelm                  Type = Type(detection.FileTypeHelm)
	TypeKubernetes            Type = Type(detection.FileTypeKubernetes)
	TypeTerraform             Type = Type(detection.FileTypeTerraform)
	TypeTerraformPlanJSON     Type = Type(detection.FileTypeTerraformPlanJSON)
	TypeTerraformPlanSnapshot Type = Type(detection.FileTypeTerraformPlanSnapshot)
	TypeYAML                  Type = Type(detection.FileTypeYAML)
	TypeJSON                  Type = Type(detection.FileTypeJSON)

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
		TypeBottlerocket,
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
		TypeComposerVendor,
		TypeJar,
		TypePom,
		TypeGradleLock,
		TypeSbtLock,
		TypeNpmPkgLock,
		TypeNodePkg,
		TypeYarn,
		TypePnpm,
		TypeNuget,
		TypeDotNetCore,
		TypePackagesProps,
		TypeCondaPkg,
		TypeCondaEnv,
		TypePythonPkg,
		TypePythonPkgEgg,
		TypePip,
		TypePipenv,
		TypePoetry,
		TypeUv,
		TypeGoBinary,
		TypeGoMod,
		TypeRustBinary,
		TypeConanLock,
		TypeCocoaPods,
		TypeSwift,
		TypePubSpecLock,
		TypeMixLock,
		TypeJulia,
		TypeSBOM,
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
		TypeUv,
		TypeGoMod,
		TypePom,
		TypeConanLock,
		TypeGradleLock,
		TypeSbtLock,
		TypeCocoaPods,
		TypeSwift,
		TypePubSpecLock,
		TypeMixLock,
		TypeCondaEnv,
		TypeComposer,
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
		TypeComposerVendor,
	}

	// TypeConfigFiles has all config file analyzers
	TypeConfigFiles = []Type{
		TypeAzureARM,
		TypeCloudFormation,
		TypeDockerfile,
		TypeHelm,
		TypeKubernetes,
		TypeTerraform,
		TypeTerraformPlanJSON,
		TypeTerraformPlanSnapshot,
		TypeYAML,
		TypeJSON,
	}
)
