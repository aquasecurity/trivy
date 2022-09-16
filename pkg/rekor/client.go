package rekor

import (
	"context"
	"net/url"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	treeIDLen = 16
	uuidLen   = 64
)

var ErrNoAttestation = xerrors.Errorf("Rekor attestations not found")

// EntryID is a hex-format string. The length of the string is 80 or 64.
// If the length is 80, it consists of two elements, the TreeID and the UUID. If the length is 64,
// it consists only of the UUID.
// cf. https://github.com/sigstore/rekor/blob/4923f60f4ae55ccd4baf28d182e8f55c2d8097d3/pkg/sharding/sharding.go#L25-L36
type EntryID struct {
	TreeID string
	UUID   string
}

func NewEntryID(entryID string) (EntryID, error) {
	switch len(entryID) {
	case treeIDLen + uuidLen:
		return EntryID{TreeID: entryID[:treeIDLen], UUID: entryID[treeIDLen:]}, nil
	case uuidLen:
		return EntryID{TreeID: "", UUID: entryID}, nil
	default:
		return EntryID{}, xerrors.Errorf("invalid Entry ID length")
	}
}

func (e EntryID) String() string {
	return e.TreeID + e.UUID
}

type Entry struct {
	Statement []byte
}

type Client struct {
	*client.Rekor
}

func NewClient(rekorURL string) (*Client, error) {
	u, err := url.Parse(rekorURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse url: %w", err)
	}

	c := client.New(
		httptransport.New(u.Host, client.DefaultBasePath, []string{u.Scheme}),
		strfmt.Default,
	)
	return &Client{Rekor: c}, nil
}

func (c *Client) Search(ctx context.Context, hash string) ([]EntryID, error) {
	log.Logger.Debugf("Search for %s in Rekor", hash)
	params := index.NewSearchIndexParamsWithContext(ctx).WithQuery(&models.SearchIndex{Hash: hash})
	resp, err := c.Index.SearchIndex(params)
	if err != nil {
		return nil, xerrors.Errorf("failed to search: %w", err)
	}

	ids := make([]EntryID, len(resp.Payload))
	for i, id := range resp.Payload {
		ids[i], err = NewEntryID(id)
		if err != nil {
			return nil, xerrors.Errorf("invalid entry UUID: %w", err)
		}
	}

	return ids, nil
}

func (c *Client) GetEntry(ctx context.Context, entryID EntryID) (Entry, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx).WithEntryUUID(entryID.String())

	// TODO: bulk search
	resp, err := c.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return Entry{}, xerrors.Errorf("failed to get log entry by UUID: %w", err)
	}

	entry, found := resp.Payload[entryID.UUID]
	if !found {
		return Entry{}, ErrNoAttestation
	}

	if entry.Attestation == nil {
		return Entry{}, ErrNoAttestation
	}

	return Entry{Statement: entry.Attestation.Data}, nil
}
