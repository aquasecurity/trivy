package cache

import (
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

const metadataFile = "metadata.json"

type Client struct {
	path string
}

type Metadata struct {
	Version int `json:",omitempty"`
}

func NewMetadata(cacheDir string) Client {
	return Client{
		path: filepath.Join(cacheDir, metadataFile),
	}
}

// Get returns the file metadata
func (c *Client) Get() (Metadata, error) {
	f, err := os.Open(c.path)
	if err != nil {
		return Metadata{}, xerrors.Errorf("unable to open a file: %w", err)
	}
	defer f.Close()

	var metadata Metadata
	if err = json.NewDecoder(f).Decode(&metadata); err != nil {
		return Metadata{}, xerrors.Errorf("unable to decode metadata: %w", err)
	}
	return metadata, nil
}

func (c *Client) Update(meta Metadata) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0744); err != nil {
		return xerrors.Errorf("mkdir error: %w", err)
	}

	f, err := os.Create(c.path)
	if err != nil {
		return xerrors.Errorf("unable to open a file: %w", err)
	}
	defer f.Close()

	if err = json.NewEncoder(f).Encode(&meta); err != nil {
		return xerrors.Errorf("unable to decode metadata: %w", err)
	}
	return nil
}

// Delete deletes the file of database metadata
func (c *Client) Delete() error {
	if err := os.Remove(c.path); err != nil {
		return xerrors.Errorf("unable to remove the metadata file: %w", err)
	}
	return nil
}
