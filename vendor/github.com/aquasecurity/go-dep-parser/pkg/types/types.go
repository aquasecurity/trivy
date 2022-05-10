package types

type Library struct {
	Name    string
	Version string
	License string `json:",omitempty"`
}
