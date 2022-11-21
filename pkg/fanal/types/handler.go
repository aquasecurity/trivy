package types

type HandlerType string

const (
	SystemFileFilteringPostHandler HandlerType = "system-file-filter"
	GoModMergePostHandler          HandlerType = "go-mod-merge"
	MisconfPostHandler             HandlerType = "misconf"
	DpkgPostHandler                HandlerType = "dpkg"
	UnpackagedPostHandler          HandlerType = "unpackaged"

	// SystemFileFilteringPostHandlerPriority should be higher than other handlers.
	// Otherwise, other handlers need to process unnecessary files.
	SystemFileFilteringPostHandlerPriority = 100

	GoModMergePostHandlerPriority = 50
	MisconfPostHandlerPriority    = 50
	DpkgPostHandlerPriority       = 50
	UnpackagedPostHandlerPriority = 50
)
