package types

type OsPackage struct {
	PkgName          string       `json:",omitempty"`
	InstalledVersion string       `json:",omitempty"`
}
