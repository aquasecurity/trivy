package hook_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
)

type fakeHook struct{}

func (h fakeHook) Version() int { return 1 }

func (h fakeHook) Type() hook.Type { return "fake" }

func (h fakeHook) Hook(info *types.BlobInfo) error {
	info.DiffID = "fake"
	return nil
}

func TestManager_Versions(t *testing.T) {
	tests := []struct {
		name    string
		disable []hook.Type
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
			disable: []hook.Type{"fake"},
			want: map[string]int{
				"fake": 0,
			},
		},
	}

	hook.RegisterHook(fakeHook{})
	defer hook.DeregisterHook("fake")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := hook.NewManager(tt.disable)
			got := m.Versions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestManager_CallHooks(t *testing.T) {
	tests := []struct {
		name    string
		disable []hook.Type
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
			disable: []hook.Type{"fake"},
			want: types.BlobInfo{
				Digest: "digest",
			},
		},
	}

	hook.RegisterHook(fakeHook{})
	defer hook.DeregisterHook("fake")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob := types.BlobInfo{
				Digest: "digest",
			}
			m := hook.NewManager(tt.disable)

			err := m.CallHooks(&blob)
			require.NoError(t, err)
			assert.Equal(t, tt.want, blob)
		})
	}
}
