package cache

import (
	"context"
	"net/http"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
)

type RemoteCache struct {
	ctx    context.Context // for custom header
	client rpcCache.Cache
}

type RemoteURL string

func NewRemoteCache(url RemoteURL, customHeaders http.Header) cache.ArtifactCache {
	ctx := client.WithCustomHeaders(context.Background(), customHeaders)
	c := rpcCache.NewCacheProtobufClient(string(url), &http.Client{})
	return &RemoteCache{ctx: ctx, client: c}
}

func (c RemoteCache) PutArtifact(imageID string, imageInfo types.ArtifactInfo) error {
	_, err := c.client.PutArtifact(c.ctx, rpc.ConvertToRpcArtifactInfo(imageID, imageInfo))
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

func (c RemoteCache) PutBlob(diffID string, layerInfo types.BlobInfo) error {
	_, err := c.client.PutBlob(c.ctx, rpc.ConvertToRpcBlobInfo(diffID, layerInfo))
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

func (c RemoteCache) MissingBlobs(imageID string, layerIDs []string) (bool, []string, error) {
	layers, err := c.client.MissingBlobs(c.ctx, rpc.ConvertToMissingBlobsRequest(imageID, layerIDs))
	if err != nil {
		return false, nil, xerrors.Errorf("unable to fetch missing layers: %w", err)
	}
	return layers.MissingArtifact, layers.MissingBlobIds, nil
}
