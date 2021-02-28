package analyzer

type Type int

// NOTE: Do not change the order of "Type" unnecessarily, as it will affect the cache.
const (
	// OS
	TypeAlpine Type = iota + 1
	TypeAmazon
	TypeDebian
	TypePhoton
	TypeCentOS
	TypeFedora
	TypeOracle
	TypeRedHatBase
	TypeSUSE
	TypeUbuntu

	// OS Package
	TypeApk
	TypeDpkg
	TypeRpm

	// Programming Language Package
	TypeBundler
	TypeCargo
	TypeComposer
	TypeJar
	TypeNpm
	TypeNuget
	TypePipenv
	TypePoetry
	TypeYarn

	// Image Config
	TypeApkCommand

	// Structured Config
	TypeYaml
	TypeTOML
	TypeJSON
	TypeDockerfile
)
