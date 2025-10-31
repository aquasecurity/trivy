package compare

// Comparer is an interface for version comparison
type Comparer interface {
	MatchVersion(currentVersion, constraint string) (bool, error)
}
