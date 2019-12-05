// +build wireinject

package server

import (
	"github.com/aquasecurity/trivy/internal/rpc/server/library"
	"github.com/google/wire"
)

func initializeLibServer() *library.Server {
	wire.Build(library.SuperSet)
	return &library.Server{}
}
