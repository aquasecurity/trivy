package config

import "strings"

type ColorMode int

const (
	AutoColor ColorMode = iota
	AlwaysColor
	NeverColor
)

func NewColorMode(s string) ColorMode {
	s = strings.ToLower(s)

	switch s {
	case "auto":
		return AutoColor
	case "true", "always":
		return AlwaysColor
	case "false", "never":
		return NeverColor
	default:
		return AutoColor
	}
}
