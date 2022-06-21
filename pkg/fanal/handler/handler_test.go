package handler_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type fakeHook struct{}

func (h fakeHook) Handle(ctx context.Context, result *analyzer.AnalysisResult, info *types.BlobInfo) error {
	info.DiffID = "fake"
	return nil
}

func (h fakeHook) Priority() int {
	return 1
}

func (h fakeHook) Version() int { return 1 }

func (h fakeHook) Type() types.HandlerType { return "fake" }

func fakehookInit(_ artifact.Option) (handler.PostHandler, error) {
	return fakeHook{}, nil
}

func TestManager_Versions(t *testing.T) {
	tests := []struct {
		name    string
		disable []types.HandlerType
		want    map[string]int
	}{
		{
			name: "happy path",
			want: map[string]int{
				"fake": 1,
			},
		},
		{
			name:    "disable hooks",
			disable: []types.HandlerType{"fake"},
			want:    map[string]int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler.RegisterPostHandlerInit("fake", fakehookInit)
			defer handler.DeregisterPostHandler("fake")
			m, err := handler.NewManager(artifact.Option{
				DisabledHandlers: tt.disable,
			})
			require.NoError(t, err)
			got := m.Versions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestManager_CallHooks(t *testing.T) {
	tests := []struct {
		name    string
		disable []types.HandlerType
		want    types.BlobInfo
	}{
		{
			name: "happy path",
			want: types.BlobInfo{
				Digest: "digest",
				DiffID: "fake",
			},
		},
		{
			name:    "disable hooks",
			disable: []types.HandlerType{"fake"},
			want: types.BlobInfo{
				Digest: "digest",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler.RegisterPostHandlerInit("fake", fakehookInit)
			defer handler.DeregisterPostHandler("fake")
			blob := types.BlobInfo{
				Digest: "digest",
			}
			m, err := handler.NewManager(artifact.Option{
				DisabledHandlers: tt.disable,
			})
			require.NoError(t, err)

			err = m.PostHandle(context.TODO(), nil, &blob)
			require.NoError(t, err)
			assert.Equal(t, tt.want, blob)
		})
	}
}
