package cache

import (
	"context"
	"net/http"

	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
)

var _ ArtifactCache = (*RemoteCache)(nil)

type RemoteOptions struct {
	ServerAddr    string
	CustomHeaders http.Header
	PathPrefix    string
}

// RemoteCache implements remote cache
type RemoteCache struct {
	ctx    context.Context // for custom header
	client rpcCache.Cache
}

// NewRemoteCache is the factory method for RemoteCache
func NewRemoteCache(ctx context.Context, opts RemoteOptions) *RemoteCache {
	ctx = client.WithCustomHeaders(ctx, opts.CustomHeaders)

	var twirpOpts []twirp.ClientOption
	if opts.PathPrefix != "" {
		twirpOpts = append(twirpOpts, twirp.WithClientPathPrefix(opts.PathPrefix))
	}
	c := rpcCache.NewCacheProtobufClient(opts.ServerAddr, xhttp.ClientWithContext(ctx), twirpOpts...)
	return &RemoteCache{
		ctx:    ctx,
		client: c,
	}
}

// PutArtifact sends artifact to remote client
func (c RemoteCache) PutArtifact(ctx context.Context, imageID string, artifactInfo types.ArtifactInfo) error {
	_, err := rpc.Retry(ctx, func() (any, error) {
		return c.client.PutArtifact(c.ctx, rpc.ConvertToRPCArtifactInfo(imageID, artifactInfo))
	})
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

// PutBlob sends blobInfo to remote client
func (c RemoteCache) PutBlob(ctx context.Context, diffID string, blobInfo types.BlobInfo) error {
	_, err := rpc.Retry(ctx, func() (any, error) {
		return c.client.PutBlob(c.ctx, rpc.ConvertToRPCPutBlobRequest(diffID, blobInfo))
	})
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

// MissingBlobs fetches missing blobs from RemoteCache
func (c RemoteCache) MissingBlobs(ctx context.Context, imageID string, layerIDs []string) (bool, []string, error) {
	layers, err := rpc.Retry(ctx, func() (*rpcCache.MissingBlobsResponse, error) {
		return c.client.MissingBlobs(c.ctx, rpc.ConvertToMissingBlobsRequest(imageID, layerIDs))
	})
	if err != nil {
		return false, nil, xerrors.Errorf("unable to fetch missing layers: %w", err)
	}
	return layers.MissingArtifact, layers.MissingBlobIds, nil
}

// DeleteBlobs removes blobs by IDs from RemoteCache
func (c RemoteCache) DeleteBlobs(ctx context.Context, blobIDs []string) error {
	_, err := rpc.Retry(ctx, func() (any, error) {
		return c.client.DeleteBlobs(c.ctx, rpc.ConvertToDeleteBlobsRequest(blobIDs))
	})
	if err != nil {
		return xerrors.Errorf("unable to delete blobs on the server: %w", err)
	}
	return nil
}
