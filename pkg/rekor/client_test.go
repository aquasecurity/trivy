package rekor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/rekor"
)

func TestClient_Search(t *testing.T) {
	type args struct {
		hash string
	}
	tests := []struct {
		name             string
		mockResponseFile string
		args             args
		want             []rekor.EntryID
		wantErr          string
	}{
		{
			name:             "happy path",
			mockResponseFile: "testdata/search-response.json",
			args: args{
				hash: "92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b",
			},
			want: []rekor.EntryID{
				{
					TreeID: "392f8ecba72f4326",
					UUID:   "eb624a7403756250b5f2ad58842a99d1653cd6f147f4ce9eda2da350bd908a55",
				},
				{
					TreeID: "392f8ecba72f4326",
					UUID:   "414eaca77bd19bf5f378725d7fd79309605a81b69cc0101f5cd3119d0a216523",
				},
				{
					TreeID: "",
					UUID:   "414eaca77bd19bf5f378725d7fd79309605a81b69cc0101f5cd3119d0a012345",
				},
			},
		},
		{
			name:             "invalid UUID",
			mockResponseFile: "testdata/search-invalid-response.json",
			args: args{
				hash: "92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b",
			},
			wantErr: "invalid entry UUID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, tt.mockResponseFile)
				return
			}))
			defer ts.Close()

			c, err := rekor.NewClient(ts.URL)
			require.NoError(t, err)

			got, err := c.Search(context.Background(), tt.args.hash)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClient_GetEntry(t *testing.T) {
	type args struct {
		uuid rekor.EntryID
	}
	tests := []struct {
		name             string
		mockResponseFile string
		args             args
		want             rekor.Entry
		wantErr          error
	}{
		{
			name:             "happy path",
			mockResponseFile: "testdata/log-entry.json",
			args: args{
				uuid: rekor.EntryID{
					TreeID: "392f8ecba72f4326",
					UUID:   "8b5b2debb565fd5cb05ae0d3935351fa3faabce558bede72e197b5722a742b1e",
				},
			},
			want: rekor.Entry{
				Statement: []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"cosign.sigstore.dev/attestation/v1","subject":[{"name":"ghcr.io/aquasecurity/trivy-test-images","digest":{"sha256":"20d3f693dcffa44d6b24eae88783324d25cc132c22089f70e4fbfb858625b062"}}],"predicate":{"Data":"\"foo\\n\"\n","Timestamp":"2022-08-26T01:17:17Z"}}`),
			},
		},
		{
			name:             "no attestation",
			mockResponseFile: "testdata/log-entry-no-attestation.json",
			args: args{
				uuid: rekor.EntryID{
					TreeID: "392f8ecba72f4326",
					UUID:   "8b5b2debb565fd5cb05ae0d3935351fa3faabce558bede72e197b5722a742b1e",
				},
			},
			wantErr: rekor.ErrNoAttestation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, tt.mockResponseFile)
				return
			}))
			defer ts.Close()

			client, err := rekor.NewClient(ts.URL)
			require.NoError(t, err)

			got, err := client.GetEntry(context.Background(), tt.args.uuid)
			require.Equal(t, tt.wantErr, err)
			require.Equal(t, tt.want, got)
		})
	}
}
