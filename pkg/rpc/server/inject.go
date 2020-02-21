// +build wireinject

package server

import (
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/rpc/server/library"
	"github.com/aquasecurity/trivy/pkg/rpc/server/ospkg"
	"github.com/google/wire"
)

func initializeScanServer(localLayerCache cache.LocalImageCache) *ScanServer {
	wire.Build(ScanSuperSet)
	return &ScanServer{}
}

func initializeOspkgServer() *ospkg.Server {
	wire.Build(ospkg.SuperSet)
	return &ospkg.Server{}
}

func initializeLibServer() *library.Server {
	wire.Build(library.SuperSet)
	return &library.Server{}
}

func initializeDBWorker(quiet bool) dbWorker {
	wire.Build(DBWorkerSuperSet)
	return dbWorker{}
}
