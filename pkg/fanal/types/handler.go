package types

type HandlerType string

const (
	SystemFileFilteringPostHandler HandlerType = "system-file-filter"
	GoModMergePostHandler          HandlerType = "go-mod-merge"
	MisconfPostHandler             HandlerType = "misconf"
	DpkgLicensePostHandler         HandlerType = "dpkg-license-adder"

	// SystemFileFilteringPostHandlerPriority should be higher than other handlers.
	// Otherwise, other handlers need to process unnecessary files.
	SystemFileFilteringPostHandlerPriority = 100

	GoModMergePostHandlerPriority  = 50
	MisconfPostHandlerPriority     = 50
	DpkgLicensePostHandlerPriority = 50
)
