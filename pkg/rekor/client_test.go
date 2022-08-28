package rekor

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/stretchr/testify/require"
)

type mockEntriesClient struct {
	entries.ClientService
	logEntryResponseFile string
}

func (c *mockEntriesClient) GetLogEntryByUUID(_ *entries.GetLogEntryByUUIDParams, _ ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	f, err := os.Open(c.logEntryResponseFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var resp entries.GetLogEntryByUUIDOK
	err = json.NewDecoder(f).Decode(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func TestClient_GetByUUID(t *testing.T) {
	type args struct {
		uuid EntryID
	}
	tests := []struct {
		name             string
		mockResponseFile string
		args             args
		want             Entry
	}{
		{
			name:             "happy path",
			mockResponseFile: "testdata/logEntryResponse.json",
			args: args{
				uuid: "8b5b2debb565fd5cb05ae0d3935351fa3faabce558bede72e197b5722a742b1e",
			},
			want: Entry{
				Statement: []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"cosign.sigstore.dev/attestation/v1","subject":[{"name":"ghcr.io/aquasecurity/trivy-test-images","digest":{"sha256":"20d3f693dcffa44d6b24eae88783324d25cc132c22089f70e4fbfb858625b062"}}],"predicate":{"Data":"\"foo\\n\"\n","Timestamp":"2022-08-26T01:17:17Z"}}`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient()
			require.NoError(t, err)

			client.c.Entries = &mockEntriesClient{logEntryResponseFile: tt.mockResponseFile}

			got, err := client.GetEntry(context.Background(), tt.args.uuid)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

type mockIndexClient struct {
	index.ClientService
	searchIndexResponseFile string
}

func (c *mockIndexClient) SearchIndex(_ *index.SearchIndexParams, _ ...index.ClientOption) (*index.SearchIndexOK, error) {
	f, err := os.Open(c.searchIndexResponseFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var resp index.SearchIndexOK
	err = json.NewDecoder(f).Decode(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil

}

func TestClient_Search(t *testing.T) {
	type args struct {
		hash string
	}
	tests := []struct {
		name             string
		mockResponseFile string
		args             args
		want             []EntryID
	}{
		{
			name:             "happy path",
			mockResponseFile: "testdata/searchResponse.json",
			args: args{
				hash: "92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b",
			},
			want: []EntryID{
				"392f8ecba72f4326eb624a7403756250b5f2ad58842a99d1653cd6f147f4ce9eda2da350bd908a55",
				"392f8ecba72f4326414eaca77bd19bf5f378725d7fd79309605a81b69cc0101f5cd3119d0a216523",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient()
			require.NoError(t, err)

			c.c.Index = &mockIndexClient{
				searchIndexResponseFile: tt.mockResponseFile,
			}

			got, err := c.Search(context.Background(), tt.args.hash)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
