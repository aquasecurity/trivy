package types

type HandlerType string

const (
	SystemFileFilteringPostHandler HandlerType = "system-file-filter"
	SystemPackagesPostHandler      HandlerType = "system-packages"
	UnpackagedPostHandler          HandlerType = "unpackaged"

	// SystemFileFilteringPostHandlerPriority should be higher than other handlers.
	// Otherwise, other handlers need to process unnecessary files.
	SystemFileFilteringPostHandlerPriority = 100
	SystemPackagesPostHandlerPriority      = 75
	UnpackagedPostHandlerPriority          = 50
)
