package types

type HandlerType string

const (
	SystemFileFilteringPostHandler HandlerType = "system-file-filter"
	GoModMergePostHandler          HandlerType = "go-mod-merge"
	MisconfPostHandler             HandlerType = "misconf"
	DpkgLicensePostHandler         HandlerType = "dpkg-license"

	// DpkgLicensePostHandlerPriority must be higher than SystemFileFilteringPostHandlerPriority
	// so that copyright files will not be filtered by system-file-filter.
	DpkgLicensePostHandlerPriority = 120

	// SystemFileFilteringPostHandlerPriority should be higher than other handlers.
	// Otherwise, other handlers need to process unnecessary files.
	SystemFileFilteringPostHandlerPriority = 100

	GoModMergePostHandlerPriority = 50
	MisconfPostHandlerPriority    = 50
)
