// +build wireinject

package server

import (
	library2 "github.com/aquasecurity/trivy/pkg/rpc/server/library"
	ospkg2 "github.com/aquasecurity/trivy/pkg/rpc/server/ospkg"
	"github.com/google/wire"
)

func initializeOspkgServer() *ospkg2.Server {
	wire.Build(ospkg2.SuperSet)
	return &ospkg2.Server{}
}

func initializeLibServer() *library2.Server {
	wire.Build(library2.SuperSet)
	return &library2.Server{}
}

func initializeDBWorker() dbWorker {
	wire.Build(SuperSet)
	return dbWorker{}
}
