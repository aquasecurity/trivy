package app

// For some reason, the version is not being injected from git tags through goreleaser
// The version is hardcoded here for now
var ver = "v0.56.2-maven-patch"

func Version() string {
	return ver
}
