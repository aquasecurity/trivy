package cache

import (
	"context"
	"net/http"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/rpc/client"

	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/rpc/layer"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

type RemoteCache struct {
	ctx    context.Context // for custom header
	client layer.Layer
}

type RemoteURL string

func NewRemoteCache(url RemoteURL, customHeaders http.Header) cache.LayerCache {
	ctx := client.WithCustomHeaders(context.Background(), customHeaders)
	client := layer.NewLayerProtobufClient(string(url), &http.Client{})
	return &RemoteCache{ctx: ctx, client: client}
}

func (c RemoteCache) PutLayer(layerID, decompressedLayerID string, layerInfo types.LayerInfo) error {
	_, err := c.client.Put(c.ctx, rpc.ConvertToRpcLayerInfo(layerID, decompressedLayerID, layerInfo))
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

func (c RemoteCache) MissingLayers(layerIDs []string) ([]string, error) {
	layers, err := c.client.MissingLayers(c.ctx, rpc.ConvertToRpcLayers(layerIDs))
	if err != nil {
		return nil, xerrors.Errorf("unable to fetch missing layers: %w", err)
	}
	return layers.LayerIds, nil
}
