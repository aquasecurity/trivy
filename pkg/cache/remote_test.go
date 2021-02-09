package cache_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	fcache "github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
)

type mockCacheServer struct {
	cache fcache.Cache
}

func (s *mockCacheServer) PutArtifact(_ context.Context, in *rpcCache.PutArtifactRequest) (*google_protobuf.Empty, error) {
	if strings.Contains(in.ArtifactId, "invalid") {
		return &google_protobuf.Empty{}, xerrors.New("invalid image ID")
	}
	return &google_protobuf.Empty{}, nil
}

func (s *mockCacheServer) PutBlob(_ context.Context, in *rpcCache.PutBlobRequest) (*google_protobuf.Empty, error) {
	if strings.Contains(in.DiffId, "invalid") {
		return &google_protobuf.Empty{}, xerrors.New("invalid layer ID")
	}
	return &google_protobuf.Empty{}, nil
}

func (s *mockCacheServer) MissingBlobs(_ context.Context, in *rpcCache.MissingBlobsRequest) (*rpcCache.MissingBlobsResponse, error) {
	var layerIDs []string
	for _, layerID := range in.BlobIds[:len(in.BlobIds)-1] {
		if strings.Contains(layerID, "invalid") {
			return nil, xerrors.New("invalid layer ID")
		}
		layerIDs = append(layerIDs, layerID)
	}
	return &rpcCache.MissingBlobsResponse{MissingArtifact: true, MissingBlobIds: layerIDs}, nil
}

func withToken(base http.Handler, token, tokenHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get(tokenHeader) {
			rpcScanner.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

func TestRemoteCache_PutArtifact(t *testing.T) {
	mux := http.NewServeMux()
	layerHandler := rpcCache.NewCacheServer(new(mockCacheServer), nil)
	mux.Handle(rpcCache.CachePathPrefix, withToken(layerHandler, "valid-token", "Trivy-Token"))
	ts := httptest.NewServer(mux)

	type args struct {
		imageID       string
		imageInfo     types.ArtifactInfo
		customHeaders http.Header
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				imageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
				imageInfo: types.ArtifactInfo{
					SchemaVersion: 1,
					Architecture:  "amd64",
					Created:       time.Time{},
					DockerVersion: "18.06",
					OS:            "linux",
					HistoryPackages: []types.Package{
						{
							Name:    "musl",
							Version: "1.2.3",
						},
					},
				},
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
		},
		{
			name: "sad path",
			args: args{
				imageID: "sha256:invalid",
				imageInfo: types.ArtifactInfo{
					SchemaVersion: 1,
					Architecture:  "amd64",
					Created:       time.Time{},
					DockerVersion: "18.06",
					OS:            "linux",
					HistoryPackages: []types.Package{
						{
							Name:    "musl",
							Version: "1.2.3",
						},
					},
				},
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
			wantErr: "twirp error internal",
		},
		{
			name: "sad path: invalid token",
			args: args{
				imageID: "sha256:invalid",
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
			err := c.PutArtifact(tt.args.imageID, tt.args.imageInfo)
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

func TestRemoteCache_PutBlob(t *testing.T) {
	mux := http.NewServeMux()
	layerHandler := rpcCache.NewCacheServer(new(mockCacheServer), nil)
	mux.Handle(rpcCache.CachePathPrefix, withToken(layerHandler, "valid-token", "Trivy-Token"))
	ts := httptest.NewServer(mux)

	type args struct {
		diffID        string
		layerInfo     types.BlobInfo
		customHeaders http.Header
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				diffID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
		},
		{
			name: "sad path",
			args: args{
				diffID: "sha256:invalid",
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
			wantErr: "twirp error internal",
		},
		{
			name: "sad path: invalid token",
			args: args{
				diffID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
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
			err := c.PutBlob(tt.args.diffID, tt.args.layerInfo)
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

func TestRemoteCache_MissingBlobs(t *testing.T) {
	mux := http.NewServeMux()
	layerHandler := rpcCache.NewCacheServer(new(mockCacheServer), nil)
	mux.Handle(rpcCache.CachePathPrefix, withToken(layerHandler, "valid-token", "Trivy-Token"))
	ts := httptest.NewServer(mux)

	type args struct {
		imageID       string
		layerIDs      []string
		customHeaders http.Header
	}
	tests := []struct {
		name                string
		args                args
		wantMissingImage    bool
		wantMissingLayerIDs []string
		wantErr             string
	}{
		{
			name: "happy path",
			args: args{
				imageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
				},
				customHeaders: http.Header{
					"Trivy-Token": []string{"valid-token"},
				},
			},
			wantMissingImage: true,
			wantMissingLayerIDs: []string{
				"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
			},
		},
		{
			name: "sad path",
			args: args{
				imageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
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
				imageID: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
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
			gotMissingImage, gotMissingLayerIDs, err := c.MissingBlobs(tt.args.imageID, tt.args.layerIDs)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantMissingImage, gotMissingImage)
			assert.Equal(t, tt.wantMissingLayerIDs, gotMissingLayerIDs)
		})
	}
}
