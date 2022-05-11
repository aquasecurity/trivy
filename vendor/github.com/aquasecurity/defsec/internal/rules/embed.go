package rules

import (
	"embed"
)

//go:embed */policies
var EmbeddedPolicyFileSystem embed.FS

//go:embed */lib
var EmbeddedLibraryFileSystem embed.FS
