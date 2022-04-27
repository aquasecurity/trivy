package rules

import (
	"embed"
)

//go:embed */lib */policies
var EmbeddedPolicyFileSystem embed.FS
