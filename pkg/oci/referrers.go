package oci

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/remote"
	"github.com/aquasecurity/trivy/pkg/set"
)

// Referrers lists the OCI 1.1 referrers of digest whose ArtifactType is one of
// artifactTypes, preserving the registry order. It returns an empty slice (not
// an error) when the registry exposes no matching referrers, so callers decide
// what "no referrers" means for them.
func Referrers(ctx context.Context, digest name.Digest, opts types.RegistryOptions,
	artifactTypes set.Set[string]) ([]v1.Descriptor, error) {
	index, err := remote.Referrers(ctx, digest, opts)
	if err != nil {
		return nil, err
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, xerrors.Errorf("unable to get referrers manifest: %w", err)
	}

	descs := lo.Filter(lo.FromPtr(manifest).Manifests, func(desc v1.Descriptor, _ int) bool {
		return artifactTypes.Contains(desc.ArtifactType)
	})
	return descs, nil
}
