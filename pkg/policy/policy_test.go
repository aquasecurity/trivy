package policy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/clock"
	fake "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func TestClient_LoadDefaultPolicies(t *testing.T) {
	tests := []struct {
		name     string
		cacheDir string
		want     []string
		wantErr  string
	}{
		{
			name:     "happy path",
			cacheDir: "testdata/happy",
			want: []string{
				"testdata/happy/policy/content/kubernetes",
				"testdata/happy/policy/content/docker",
			},
		},
		{
			name:     "empty roots",
			cacheDir: "testdata/empty",
			want: []string{
				"testdata/empty/policy/content",
			},
		},
		{
			name:     "broken manifest",
			cacheDir: "testdata/broken",
			want:     []string{},
			wantErr:  "json decode error",
		},
		{
			name:     "no such file",
			cacheDir: "testdata/unknown",
			want:     []string{},
			wantErr:  "manifest file open error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.SetCacheDir(tt.cacheDir)

			c := policy.NewClient()
			got, err := c.LoadDefaultPolicies()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClient_NeedsUpdate(t *testing.T) {
	type fields struct {
		clock clock.Clock
	}
	tests := []struct {
		name           string
		fields         fields
		metadata       interface{}
		createMetadata bool
		wantEtag       string
		wantNeeds      bool
	}{
		{
			name: "needs update",
			fields: fields{
				clock: fake.NewFakeClock(time.Date(2021, 1, 2, 1, 0, 0, 0, time.UTC)),
			},
			metadata: policy.Metadata{
				Etag:          `"6065cba4-11d4"`,
				LastUpdatedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			createMetadata: true,
			wantEtag:       `"6065cba4-11d4"`,
			wantNeeds:      true,
		},
		{
			name: "no need",
			fields: fields{
				clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			},
			metadata: policy.Metadata{
				Etag:          `"6065cba4-11d4"`,
				LastUpdatedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			createMetadata: true,
			wantEtag:       "",
			wantNeeds:      false,
		},
		{
			name: "sad: non-existent metadata",
			fields: fields{
				clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			},
			metadata: policy.Metadata{
				Etag:          `"6065cba4-11d4"`,
				LastUpdatedAt: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			createMetadata: false,
			wantEtag:       "",
			wantNeeds:      true,
		},
		{
			name: "sad: broken metadata",
			fields: fields{
				clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			},
			metadata:       `"6065cba4-11d4"`,
			createMetadata: true,
			wantEtag:       "",
			wantNeeds:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up a temporary directory
			tmpDir := t.TempDir()
			utils.SetCacheDir(tmpDir)

			b, err := json.Marshal(tt.metadata)
			require.NoError(t, err)

			// Create a policy directory
			err = os.MkdirAll(filepath.Join(tmpDir, "policy"), os.ModePerm)
			require.NoError(t, err)

			if tt.createMetadata {
				// Write a metadata file
				metadataPath := filepath.Join(tmpDir, "policy", "metadata.json")
				err = os.WriteFile(metadataPath, b, os.ModePerm)
				require.NoError(t, err)
			}

			// Assert results
			c := policy.NewClient(policy.WithClock(tt.fields.clock))
			gotEtag, gotNeeds := c.NeedsUpdate()
			assert.Equal(t, tt.wantEtag, gotEtag)
			assert.Equal(t, tt.wantNeeds, gotNeeds)
		})
	}
}

func TestClient_DownloadDefaultPolicies(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("If-None-Match") == `"6065cba4-11d4"`:
			w.Header().Set("Etag", `"6065cba4-11d4"`)
			w.WriteHeader(http.StatusNotModified)
		default:
			w.Header().Set("Etag", `"6065cba4-11d4"`)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	type fields struct {
		url   string
		clock clock.Clock
	}
	tests := []struct {
		name    string
		etag    string
		fields  fields
		want    *policy.Metadata
		wantErr string
	}{
		{
			name: "happy path",
			etag: "",
			fields: fields{
				url:   ts.URL,
				clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			},
			want: &policy.Metadata{
				Etag:          `"6065cba4-11d4"`,
				LastUpdatedAt: time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "no update",
			etag: `"6065cba4-11d4"`,
			fields: fields{
				url:   ts.URL,
				clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			},
		},
		{
			name: "invalid url",
			etag: `"6065cba4-11d4"`,
			fields: fields{
				url:   `!"#$%&`,
				clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			},
			wantErr: "invalid URL escape",
		},
		{
			name: "unreachable host",
			etag: `"6065cba4-11d4"`,
			fields: fields{
				url:   "http://localhost:1",
				clock: fake.NewFakeClock(time.Date(2021, 1, 1, 1, 0, 0, 0, time.UTC)),
			},
			wantErr: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			utils.SetCacheDir(tempDir)

			c := policy.NewClient(policy.WithClock(tt.fields.clock), policy.WithBundleURL(tt.fields.url))
			err := c.DownloadDefaultPolicies(context.Background(), tt.etag)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			// Assert metadata.json
			if tt.want != nil {
				metadata := filepath.Join(tempDir, "policy", "metadata.json")
				b, err := os.ReadFile(metadata)
				require.NoError(t, err)

				got := new(policy.Metadata)
				err = json.Unmarshal(b, got)
				require.NoError(t, err)

				assert.Equal(t, tt.want, got)
			}
		})
	}
}
