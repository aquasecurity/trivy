package types

type OsPackage struct {
	PkgName          string       `json:",omitempty"`
	InstalledVersion string       `json:",omitempty"`

	Package
}

type Package struct {
	Title          string         `json:",omitempty"`
	Description    string         `json:",omitempty"`
	References     []string       `json:",omitempty"`
}
