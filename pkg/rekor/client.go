package rekor

import (
	"context"
	"fmt"
	"net/url"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"golang.org/x/xerrors"
)

const (
	rekorServer = "https://rekor.sigstore.dev"
)

type Entry struct {
	Statement []byte
}

type Client struct {
	c *client.Rekor
}

func NewClient() (*Client, error) {
	u, err := url.Parse(rekorServer)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse url: %w", err)
	}

	c := client.New(
		httptransport.New(u.Host, client.DefaultBasePath, []string{u.Scheme}),
		strfmt.Default,
	)
	return &Client{c: c}, nil
}

func (c *Client) Search(ctx context.Context, hash string) ([]string, error) {
	params := index.NewSearchIndexParamsWithContext(ctx).WithQuery(&models.SearchIndex{Hash: hash})

	resp, err := c.c.Index.SearchIndex(params)
	if err != nil {
		return nil, xerrors.Errorf("failed to search: %w", err)
	}
	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("entries not found")
	}

	return resp.Payload, nil
}

func (c *Client) GetByEntryUUID(ctx context.Context, entryUUID string) (Entry, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx).WithEntryUUID(entryUUID)

	resp, err := c.c.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return Entry{}, xerrors.Errorf("failed to get log entry by UUID: %w", err)
	}

	// EntryUUID is TreeID(8 bytes)+UUID(32 bytes) or UUID(32 bytes)
	// cf. https://github.com/sigstore/rekor/blob/4923f60f4ae55ccd4baf28d182e8f55c2d8097d3/pkg/sharding/sharding.go#L25-L36
	uuid, err := sharding.GetUUIDFromIDString(params.EntryUUID)
	if err != nil {
		return Entry{}, xerrors.Errorf("failed to get UUID from Entry UUID: %w", err)
	}

	entry, found := resp.Payload[uuid]
	if !found {
		return Entry{}, fmt.Errorf("entry not found")
	}

	if entry.Attestation == nil {
		return Entry{}, fmt.Errorf("attestation not found")
	}

	return Entry{Statement: entry.Attestation.Data}, nil
}
