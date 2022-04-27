package metadata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

const metadataFile = "metadata.json"

type Metadata struct {
	Version      int `json:",omitempty"`
	NextUpdate   time.Time
	UpdatedAt    time.Time
	DownloadedAt time.Time // This field will be filled after downloading.
}

// Client defines the file meta
type Client struct {
	filePath string
}

// NewClient is the factory method for the metadata Client
func NewClient(cacheDir string) Client {
	filePath := Path(cacheDir)
	return Client{
		filePath: filePath,
	}
}

// Path returns the metaData file path
func Path(cacheDir string) string {
	dbDir := db.Dir(cacheDir)
	return filepath.Join(dbDir, metadataFile)
}

// Get returns the file metadata
func (c Client) Get() (Metadata, error) {
	f, err := os.Open(c.filePath)
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

func (c Client) Update(meta Metadata) error {
	if err := os.MkdirAll(filepath.Dir(c.filePath), 0744); err != nil {
		return xerrors.Errorf("mkdir error: %w", err)
	}

	f, err := os.Create(c.filePath)
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
func (c Client) Delete() error {
	if err := os.Remove(c.filePath); err != nil {
		return xerrors.Errorf("unable to remove the metadata file: %w", err)
	}
	return nil
}
