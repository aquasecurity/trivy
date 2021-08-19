package analyzer

type Type string

const (
	// OS
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

	// Programming Language Package
	TypeBundler   Type = "bundler"
	TypeCargo     Type = "cargo"
	TypeComposer  Type = "composer"
	TypeJar       Type = "jar"
	TypeNpm       Type = "npm"
	TypeNuget     Type = "nuget"
	TypePythonPkg Type = "python-pkg"
	TypePip       Type = "pip"
	TypePipenv    Type = "pipenv"
	TypePoetry    Type = "poetry"
	TypeWheel     Type = "wheel"
	TypeYarn      Type = "yarn"
	TypeGoBinary  Type = "gobinary"
	TypeGoMod     Type = "gomod"

	// Image Config
	TypeApkCommand Type = "apk-command"

	// Structured Config
	TypeYaml       Type = "yaml"
	TypeTOML       Type = "toml"
	TypeJSON       Type = "json"
	TypeDockerfile Type = "dockerfile"
	TypeHCL        Type = "hcl"
	TypeTerraform  Type = "terraform"
)
