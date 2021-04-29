package library

const (
	Bundler  = "bundler"
	Cargo    = "cargo"
	Composer = "composer"
	Npm      = "npm"
	NuGet    = "nuget"
	Pipenv   = "pipenv"
	Poetry   = "poetry"
	Yarn     = "yarn"
	Jar      = "jar"
	GoBinary = "gobinary"
)

var (
	IgnoreDirs = []string{"node_modules", "vendor"}
)
