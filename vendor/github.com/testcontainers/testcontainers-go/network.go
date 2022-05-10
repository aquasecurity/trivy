package testcontainers

import (
	"context"

	"github.com/docker/docker/api/types"
)

// NetworkProvider allows the creation of networks on an arbitrary system
type NetworkProvider interface {
	CreateNetwork(context.Context, NetworkRequest) (Network, error)            // create a network
	GetNetwork(context.Context, NetworkRequest) (types.NetworkResource, error) // get a network
}

// Network allows getting info about a single network instance
type Network interface {
	Remove(context.Context) error // removes the network
}

// NetworkRequest represents the parameters used to get a network
type NetworkRequest struct {
	Driver         string
	CheckDuplicate bool
	Internal       bool
	EnableIPv6     bool
	Name           string
	Labels         map[string]string
	Attachable     bool

	SkipReaper  bool   // indicates whether we skip setting up a reaper for this
	ReaperImage string //alternative reaper registry
}
