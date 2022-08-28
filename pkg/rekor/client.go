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
	"golang.org/x/xerrors"
)

const (
	rekorServer = "https://rekor.sigstore.dev"
)
const TreeIDLen = 16
const UUIDLen = 64

// EntryID is a hex-format string. The length of the string is 80.
// It consists of two elements, the TreeID and the UUID.
// cf. https://github.com/sigstore/rekor/blob/4923f60f4ae55ccd4baf28d182e8f55c2d8097d3/pkg/sharding/sharding.go#L25-L36
type EntryID string

func NewEntryID(entryID string) (EntryID, error) {
	if len(entryID) == TreeIDLen+UUIDLen {
		return EntryID(entryID), nil
	}
	return "", xerrors.Errorf("invalid Entry ID length")
}

func (e EntryID) UUID() string {
	return string(e)[TreeIDLen:]
}

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

func (c *Client) Search(ctx context.Context, hash string) ([]EntryID, error) {
	params := index.NewSearchIndexParamsWithContext(ctx).WithQuery(&models.SearchIndex{Hash: hash})

	resp, err := c.c.Index.SearchIndex(params)
	if err != nil {
		return nil, xerrors.Errorf("failed to search: %w", err)
	}
	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("entries not found")
	}

	ids := make([]EntryID, len(resp.Payload))
	for i, id := range resp.Payload {
		ids[i], err = NewEntryID(id)
		if err != nil {
			return nil, xerrors.Errorf("invalidate entry UUID: %w", err)
		}
	}

	return ids, nil
}

func (c *Client) GetEntry(ctx context.Context, entryID EntryID) (Entry, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx).WithEntryUUID(string(entryID))

	resp, err := c.c.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return Entry{}, xerrors.Errorf("failed to get log entry by UUID: %w", err)
	}

	entry, found := resp.Payload[entryID.UUID()]
	if !found {
		return Entry{}, fmt.Errorf("entry not found")
	}

	if entry.Attestation == nil {
		return Entry{}, fmt.Errorf("attestation not found")
	}

	return Entry{Statement: entry.Attestation.Data}, nil
}
