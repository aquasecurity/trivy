package name_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/image/name"
)

func TestReference_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		ref  name.Reference
		want string
	}{
		{
			name: "valid reference with tag",
			ref:  testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:latest"),
			want: `"ghcr.io/aquasecurity/trivy:latest"`,
		},
		{
			name: "valid reference with digest",
			ref:  testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"),
			want: `"ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"`,
		},
		{
			name: "empty reference",
			ref:  name.Reference{},
			want: `""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.ref)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestReference_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		want        string
		wantIsEmpty bool
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name:        "valid reference with tag",
			json:        `"ghcr.io/aquasecurity/trivy:latest"`,
			want:        "ghcr.io/aquasecurity/trivy:latest",
			wantIsEmpty: false,
			wantErr:     assert.NoError,
		},
		{
			name:        "valid reference with digest",
			json:        `"ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"`,
			want:        "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			wantIsEmpty: false,
			wantErr:     assert.NoError,
		},
		{
			name:        "empty reference",
			json:        `""`,
			want:        "",
			wantIsEmpty: true,
			wantErr:     assert.NoError,
		},
		{
			name:    "invalid reference",
			json:    `"not a valid reference!"`,
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r name.Reference
			err := json.Unmarshal([]byte(tt.json), &r)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.wantIsEmpty, r.IsZero())
			if !r.IsZero() {
				assert.Equal(t, tt.want, r.String())
			}
		})
	}
}

func TestReference_String(t *testing.T) {
	tests := []struct {
		name string
		ref  name.Reference
		want string
	}{
		{
			name: "ghcr.io with tag",
			ref:  testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:latest"),
			want: "ghcr.io/aquasecurity/trivy:latest",
		},
		{
			name: "ghcr.io with digest",
			ref:  testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"),
			want: "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "docker.io implicit",
			ref:  testutil.MustParseReference(t, "aquasecurity/trivy:latest"),
			want: "aquasecurity/trivy:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ref.String())
		})
	}
}

func TestReference_Context(t *testing.T) {
	tests := []struct {
		name string
		ref  name.Reference
		want string
	}{
		{
			name: "ghcr.io with tag",
			ref:  testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:latest"),
			want: "ghcr.io/aquasecurity/trivy",
		},
		{
			name: "ghcr.io with digest",
			ref:  testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"),
			want: "ghcr.io/aquasecurity/trivy",
		},
		{
			name: "docker.io implicit",
			ref:  testutil.MustParseReference(t, "aquasecurity/trivy:latest"),
			want: "index.docker.io/aquasecurity/trivy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ref.Context().String())
		})
	}
}

func TestReference_IsEmpty(t *testing.T) {
	tests := []struct {
		name string
		ref  name.Reference
		want bool
	}{
		{
			name: "non-empty reference",
			ref:  testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:latest"),
			want: false,
		},
		{
			name: "empty reference",
			ref:  name.Reference{},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ref.IsZero())
		})
	}
}

func TestReference_JSONRoundTrip(t *testing.T) {
	ref := testutil.MustParseReference(t, "ghcr.io/aquasecurity/trivy:v0.65.0")

	// Marshal to JSON
	data, err := json.Marshal(ref)
	require.NoError(t, err)

	// Unmarshal from JSON
	var decoded name.Reference
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify the decoded reference matches the original
	assert.Equal(t, ref.String(), decoded.String())
	assert.Equal(t, ref.Context().String(), decoded.Context().String())
}
