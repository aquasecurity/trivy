package ospkgid

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	genericTypes "github.com/aquasecurity/trivy/pkg/types"
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
		blob.PackageInfos = overwritePkgIdentifiers(blob.PackageInfos, blob.OS)
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

// overwritePkgIdentifiers overwrites package identifiers on the packages available
// on the provided PackageInfo list adding missing OS metadata to existing PURLs
// This is useful to overwrite identifiers for packages added by pkg (apk, rpm, etc.) analyzers
func overwritePkgIdentifiers(pkgInfos []types.PackageInfo, os types.OS) []types.PackageInfo {
	if os.Family == "" {
		return pkgInfos
	}

	metadata := genericTypes.Metadata{
		OS: &os,
	}
	for i, pkgInfo := range pkgInfos {
		for j, pkg := range pkgInfo.Packages {
			mewIdentifier := purl.NewPackageIdentifier(os.Family, metadata, pkg)
			pkgInfos[i].Packages[j].Identifier.PURL = mewIdentifier.PURL
		}
	}
	return pkgInfos
}
