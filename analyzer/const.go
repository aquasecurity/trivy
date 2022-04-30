package analyzer

type Type string

const (
	// ======
	//   OS
	// ======
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

	// OS Package
	TypeApk  Type = "apk"
	TypeDpkg Type = "dpkg"
	TypeRpm  Type = "rpm"

	// OS Package Repository
	TypeApkRepo Type = "apk-repo"

	// ============================
	// Programming Language Package
	// ============================

	// Ruby
	TypeBundler Type = "bundler"
	TypeGemSpec Type = "gemspec"

	// Rust
	TypeCargo Type = "cargo"

	// PHP
	TypeComposer Type = "composer"

	// Java
	TypeJar Type = "jar"
	TypePom Type = "pom"

	// Node.js
	TypeNpmPkgLock Type = "npm"
	TypeNodePkg    Type = "node-pkg"
	TypeYarn       Type = "yarn"

	// .NET
	TypeNuget Type = "nuget"

	// Python
	TypePythonPkg Type = "python-pkg"
	TypePip       Type = "pip"
	TypePipenv    Type = "pipenv"
	TypePoetry    Type = "poetry"

	// Go
	TypeGoBinary Type = "gobinary"
	TypeGoMod    Type = "gomod"

	// ============
	// Image Config
	// ============
	TypeApkCommand Type = "apk-command"

	// =================
	// Structured Config
	// =================
	TypeYaml           Type = "yaml"
	TypeTOML           Type = "toml"
	TypeJSON           Type = "json"
	TypeDockerfile     Type = "dockerfile"
	TypeHCL            Type = "hcl"
	TypeTerraform      Type = "terraform"
	TypeCloudFormation Type = "cloudFormation"

	// ========
	// Secrets
	// ========
	TypeSecret Type = "secret"

	// =======
	// Red Hat
	// =======
	TypeRedHatContentManifestType = "redhat-content-manifest"
	TypeRedHatDockerfileType      = "redhat-dockerfile"
)

var (
	// TypeOSes has all OS-related analyzers
	TypeOSes = []Type{TypeAlpine, TypeAmazon, TypeDebian, TypePhoton, TypeCentOS,
		TypeRocky, TypeAlma, TypeFedora, TypeOracle, TypeRedHatBase, TypeSUSE, TypeUbuntu,
		TypeApk, TypeDpkg, TypeRpm,
	}

	// TypeLanguages has all language analyzers
	TypeLanguages = []Type{TypeBundler, TypeGemSpec, TypeCargo, TypeComposer, TypeJar, TypePom,
		TypeNpmPkgLock, TypeNodePkg, TypeYarn, TypeNuget, TypePythonPkg, TypePip, TypePipenv,
		TypePoetry, TypeGoBinary, TypeGoMod,
	}

	// TypeLockfiles has all lock file analyzers
	TypeLockfiles = []Type{TypeBundler, TypeNpmPkgLock, TypeYarn,
		TypePip, TypePipenv, TypePoetry, TypeGoMod, TypePom,
	}

	// TypeIndividualPkgs has all analyzers for individual packages
	TypeIndividualPkgs = []Type{TypeGemSpec, TypeNodePkg, TypePythonPkg, TypeGoBinary, TypeJar}

	// TypeConfigFiles has all config file analyzers
	TypeConfigFiles = []Type{TypeYaml, TypeTOML, TypeJSON, TypeDockerfile, TypeHCL, TypeTerraform, TypeCloudFormation}
)
