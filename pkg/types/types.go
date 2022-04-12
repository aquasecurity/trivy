package types

type Library struct {
	Name     string
	Version  string
	Indirect bool
	License  string `json:",omitempty"`
}
