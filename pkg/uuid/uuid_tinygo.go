//go:build tinygo.wasm

package uuid

// TinyGo doesn't work with github.com/google/uuid

type UUID string

func (UUID) String() string { return "" }

const Nil = ""

func New() UUID { return "" }
