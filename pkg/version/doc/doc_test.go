package doc_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/version/doc"
)

func TestBaseURL(t *testing.T) {
	tests := []struct {
		name string
		ver  string
		want string
	}{
		{
			name: "dev",
			ver:  "dev",
			want: "https://trivy.dev/dev",
		},
		{
			name: "semver",
			ver:  "0.52.0",
			want: "https://trivy.dev/v0.52",
		},
		{
			name: "with v prefix",
			ver:  "v0.52.0",
			want: "https://trivy.dev/v0.52",
		},
		{
			name: "pre-release",
			ver:  "0.52.0-beta1",
			want: "https://trivy.dev/dev",
		},
		{
			name: "non-semver",
			ver:  "1",
			want: "https://trivy.dev/dev",
		},
		{
			name: "empty",
			ver:  "",
			want: "https://trivy.dev/dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := doc.BaseURL(tt.ver)
			require.Equal(t, tt.want, got.String())
		})
	}
}

func TestURL(t *testing.T) {
	tests := []struct {
		name     string
		rawPath  string
		fragment string
		want     string
	}{
		{
			name:    "path without slash",
			rawPath: "foo",
			want:    "https://trivy.dev/dev/foo",
		},
		{
			name:    "path with leading slash",
			rawPath: "/foo",
			want:    "https://trivy.dev/dev/foo",
		},
		{
			name:    "path with slash",
			rawPath: "foo/bar",
			want:    "https://trivy.dev/dev/foo/bar",
		},
		{
			name:     "path with fragment",
			rawPath:  "foo",
			fragment: "bar",
			want:     "https://trivy.dev/dev/foo#bar",
		},
		{
			name:    "empty",
			rawPath: "",
			want:    "https://trivy.dev/dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := doc.URL(tt.rawPath, tt.fragment)
			require.Equal(t, tt.want, got)
		})
	}
}
