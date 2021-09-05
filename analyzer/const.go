package analyzer

type Type string

const (
	// ======
	//   OS
	// ======
	TypeAlpine     Type = "alpine"
	TypeAmazon     Type = "amazon"
	TypeDebian     Type = "debian"
	TypePhoton     Type = "photon"
	TypeCentOS     Type = "centos"
	TypeFedora     Type = "fedora"
	TypeOracle     Type = "oracle"
	TypeRedHatBase Type = "redhat"
	TypeSUSE       Type = "suse"
	TypeUbuntu     Type = "ubuntu"

	// OS Package
	TypeApk  Type = "apk"
	TypeDpkg Type = "dpkg"
	TypeRpm  Type = "rpm"

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
	TypeWheel     Type = "wheel"

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
	TypeYaml       Type = "yaml"
	TypeTOML       Type = "toml"
	TypeJSON       Type = "json"
	TypeDockerfile Type = "dockerfile"
	TypeHCL        Type = "hcl"
	TypeTerraform  Type = "terraform"
)
