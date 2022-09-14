package rekor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/rekor"
	"github.com/stretchr/testify/require"
)

func TestClient_GetEntry(t *testing.T) {
	type args struct {
		uuid rekor.EntryID
	}
	tests := []struct {
		name             string
		mockResponseFile string
		args             args
		want             rekor.Entry
	}{
		{
			name:             "happy path",
			mockResponseFile: "testdata/logEntryResponse.json",
			args: args{
				uuid: "392f8ecba72f43268b5b2debb565fd5cb05ae0d3935351fa3faabce558bede72e197b5722a742b1e",
			},
			want: rekor.Entry{
				Statement: []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"cosign.sigstore.dev/attestation/v1","subject":[{"name":"ghcr.io/aquasecurity/trivy-test-images","digest":{"sha256":"20d3f693dcffa44d6b24eae88783324d25cc132c22089f70e4fbfb858625b062"}}],"predicate":{"Data":"\"foo\\n\"\n","Timestamp":"2022-08-26T01:17:17Z"}}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, r *http.Request) {
				content, err := os.ReadFile(tt.mockResponseFile)
				if err != nil {
					http.Error(res, err.Error(), http.StatusInternalServerError)
					return
				}
				res.Header().Set("Content-Type", "application/json")
				res.Write(content)
				return
			}))
			defer ts.Close()

			client, err := rekor.NewClient(ts.URL)
			require.NoError(t, err)

			got, err := client.GetEntry(context.Background(), tt.args.uuid)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestClient_Search(t *testing.T) {
	type args struct {
		hash string
	}
	tests := []struct {
		name             string
		mockResponseFile string
		args             args
		want             []rekor.EntryID
	}{
		{
			name:             "happy path",
			mockResponseFile: "testdata/searchResponse.json",
			args: args{
				hash: "92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b",
			},
			want: []rekor.EntryID{
				"392f8ecba72f4326eb624a7403756250b5f2ad58842a99d1653cd6f147f4ce9eda2da350bd908a55",
				"392f8ecba72f4326414eaca77bd19bf5f378725d7fd79309605a81b69cc0101f5cd3119d0a216523",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, r *http.Request) {
				content, err := os.ReadFile(tt.mockResponseFile)
				if err != nil {
					http.Error(res, err.Error(), http.StatusInternalServerError)
					return
				}
				res.Header().Set("Content-Type", "application/json")
				res.Write(content)
				return
			}))
			defer ts.Close()

			c, err := rekor.NewClient(ts.URL)
			require.NoError(t, err)

			got, err := c.Search(context.Background(), tt.args.hash)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
