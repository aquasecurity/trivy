package types

type HandlerType string

const (
	SystemFileFilteringPostHandler HandlerType = "system-file-filter"
	MisconfPostHandler             HandlerType = "misconf"
	UnpackagedPostHandler          HandlerType = "unpackaged"

	// SystemFileFilteringPostHandlerPriority should be higher than other handlers.
	// Otherwise, other handlers need to process unnecessary files.
	SystemFileFilteringPostHandlerPriority = 100

	MisconfPostHandlerPriority    = 50
	UnpackagedPostHandlerPriority = 50
)
