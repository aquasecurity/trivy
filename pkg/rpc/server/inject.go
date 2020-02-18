// +build wireinject

package server

import (
	"github.com/aquasecurity/fanal/cache"
	"github.com/google/wire"
)

func initializeScanServer(localLayerCache cache.LocalLayerCache) *ScanServer {
	wire.Build(ScanSuperSet)
	return &ScanServer{}
}

func initializeDBWorker(quiet bool) dbWorker {
	wire.Build(DBWorkerSuperSet)
	return dbWorker{}
}
