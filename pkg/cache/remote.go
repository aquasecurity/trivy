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

func NewRemoteCache(url RemoteURL, customHeaders http.Header) cache.ImageCache {
	ctx := client.WithCustomHeaders(context.Background(), customHeaders)
	c := rpcCache.NewCacheProtobufClient(string(url), &http.Client{})
	return &RemoteCache{ctx: ctx, client: c}
}

func (c RemoteCache) PutImage(imageID string, imageInfo types.ImageInfo) error {
	_, err := c.client.PutImage(c.ctx, rpc.ConvertToRpcImageInfo(imageID, imageInfo))
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

func (c RemoteCache) PutLayer(diffID string, layerInfo types.LayerInfo) error {
	_, err := c.client.PutLayer(c.ctx, rpc.ConvertToRpcLayerInfo(diffID, layerInfo))
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

func (c RemoteCache) MissingLayers(imageID string, layerIDs []string) (bool, []string, error) {
	layers, err := c.client.MissingLayers(c.ctx, rpc.ConvertToMissingLayersRequest(imageID, layerIDs))
	if err != nil {
		return false, nil, xerrors.Errorf("unable to fetch missing layers: %w", err)
	}
	return layers.MissingImage, layers.MissingLayerIds, nil
}
