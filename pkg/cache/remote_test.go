package cache_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	fcache "github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/rpc/detector"
	rpcLayer "github.com/aquasecurity/trivy/rpc/layer"
)

type mockLayerServer struct {
	cache fcache.Cache
}

func (s *mockLayerServer) Put(_ context.Context, in *rpcLayer.PutRequest) (*google_protobuf.Empty, error) {
	if strings.Contains(in.LayerId, "invalid") {
		return &google_protobuf.Empty{}, xerrors.New("invalid layer ID")
	}
	return &google_protobuf.Empty{}, nil
}

func (s *mockLayerServer) MissingLayers(_ context.Context, in *rpcLayer.Layers) (*rpcLayer.Layers, error) {
	var layerIDs []string
	for _, layerID := range in.LayerIds[:len(in.LayerIds)-1] {
		if strings.Contains(layerID, "invalid") {
			fmt.Println(layerID)
			return nil, xerrors.New("invalid layer ID")
		}
		layerIDs = append(layerIDs, layerID)
	}
	return &rpcLayer.Layers{LayerIds: layerIDs}, nil
}

func withToken(base http.Handler, token, tokenHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get(tokenHeader) {
			detector.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

func TestRemoteCache_PutLayer(t *testing.T) {
	mux := http.NewServeMux()
	layerHandler := rpcLayer.NewLayerServer(new(mockLayerServer), nil)
	mux.Handle(rpcLayer.LayerPathPrefix, withToken(layerHandler, "valid-token", "Trivy-Token"))
	ts := httptest.NewServer(mux)

	type args struct {
		layerID             string
		decompressedLayerID string
		layerInfo           types.LayerInfo
		customHeaders       http.Header
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				layerID:             "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				decompressedLayerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
		},
		{
			name: "sad path",
			args: args{
				layerID:             "sha256:invalid",
				decompressedLayerID: "sha256:invalid",
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
			wantErr: "twirp error internal",
		},
		{
			name: "sad path: invalid token",
			args: args{
				layerID:             "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				decompressedLayerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				customHeaders: http.Header{
					"Trivy-Token": []string{"invalid-token"},
				},
			},
			wantErr: "twirp error unauthenticated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewRemoteCache(cache.RemoteURL(ts.URL), tt.args.customHeaders)
			err := c.PutLayer(tt.args.layerID, tt.args.decompressedLayerID, tt.args.layerInfo)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}
		})
	}
}

func TestRemoteCache_MissingLayers(t *testing.T) {
	mux := http.NewServeMux()
	layerHandler := rpcLayer.NewLayerServer(new(mockLayerServer), nil)
	mux.Handle(rpcLayer.LayerPathPrefix, withToken(layerHandler, "valid-token", "Trivy-Token"))
	ts := httptest.NewServer(mux)

	type args struct {
		layerIDs      []string
		customHeaders http.Header
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				},
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
			want: []string{
				"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
			},
		},
		{
			name: "sad path",
			args: args{
				layerIDs: []string{
					"sha256:invalid",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				},
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
			wantErr: "twirp error internal",
		},
		{
			name: "sad path with invalid token",
			args: args{
				layerIDs: []string{
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				},
				customHeaders: http.Header{
					"Trivy-Token": []string{"invalid-token"},
				},
			},
			wantErr: "twirp error unauthenticated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewRemoteCache(cache.RemoteURL(ts.URL), tt.args.customHeaders)
			got, err := c.MissingLayers(tt.args.layerIDs)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
