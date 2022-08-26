package rekor

import (
	"fmt"
	"time"

	sclient "github.com/sigstore/rekor/pkg/client"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"golang.org/x/xerrors"
)

const (
	rekorServer = "https://rekor.sigstore.dev"
	// rekor-cli use 30s as the default value
	// cf. https://github.com/sigstore/rekor/blob/f9f283ecab17c14d9a3d5aac5084cc95aabd30e0/cmd/rekor-cli/app/root.go#L65
	timeOut = 30 * time.Second
)

type Record struct {
	Statement []byte
}

type Client struct {
	c *rclient.Rekor
}

func NewClient() (*Client, error) {
	c, err := sclient.GetRekorClient(rekorServer)
	if err != nil {
		return nil, xerrors.Errorf("failed to create rekor client: %w", err)
	}

	return &Client{c: c}, nil
}

func (c *Client) Search(hash string) ([]string, error) {

	params := index.NewSearchIndexParams()

	params.SetTimeout(timeOut)

	params.Query = &models.SearchIndex{}
	params.Query.Hash = hash

	resp, err := c.c.Index.SearchIndex(params)
	if err != nil {
		return nil, xerrors.Errorf("failed to search: %w", err)
	}
	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("no matching entries found")
	}

	return resp.Payload, nil
}

func (c *Client) GetByEntryUUID(entryUUID string) (Record, error) {
	params := entries.NewGetLogEntryByUUIDParams()

	params.SetTimeout(timeOut)
	params.EntryUUID = entryUUID

	resp, err := c.c.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return Record{}, xerrors.Errorf("failed to get log entry by UUID: %w", err)
	}

	// Entry UUID is TreeID(8 bytes) + UUID(32 bytes) or UUID(32 bytes)
	// cf. https://github.com/sigstore/rekor/blob/4923f60f4ae55ccd4baf28d182e8f55c2d8097d3/pkg/sharding/sharding.go#L25-L36
	uuid, err := sharding.GetUUIDFromIDString(params.EntryUUID)
	if err != nil {
		return Record{}, xerrors.Errorf("failed to get UUID from Entry UUID: %w", err)
	}

	for k, entry := range resp.Payload {
		if k == uuid {
			return Record{Statement: entry.Attestation.Data}, nil
		}
	}

	return Record{}, fmt.Errorf("record not found")
}
