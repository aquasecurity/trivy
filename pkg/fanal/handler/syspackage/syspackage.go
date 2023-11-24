package syspackage

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
)

func init() {
	handler.RegisterPostHandlerInit(types.SystemPackagesPostHandler, newSystemPackagesPostHandler)
}

const version = 1

type systemPackagesPostHandler struct{}

func newSystemPackagesPostHandler(artifact.Option) (handler.PostHandler, error) {
	return systemPackagesPostHandler{}, nil
}

// Handle overwrites package identifiers for OS packages which original ones miss OS
// metadata info since they were generated in pkg (apk, rpm, etc.) analyzers
func (h systemPackagesPostHandler) Handle(_ context.Context, _ *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	if blob != nil && len(blob.PackageInfos) > 0 {
		blob.PackageInfos = purl.OverwritePkgIdentifiers(blob.PackageInfos, blob.OS)
	}

	return nil
}

func (h systemPackagesPostHandler) Version() int {
	return version
}

func (h systemPackagesPostHandler) Type() types.HandlerType {
	return types.SystemPackagesPostHandler
}

func (h systemPackagesPostHandler) Priority() int {
	return types.SystemPackagesPostHandlerPriority
}
