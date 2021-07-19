// +build integration

package integration

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

var update = flag.Bool("update", false, "update golden files")

func gunzipDB(t *testing.T) string {
	gz, err := os.Open("testdata/trivy.db.gz")
	require.NoError(t, err)

	zr, err := gzip.NewReader(gz)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	dbPath := db.Path(tmpDir)
	dbDir := filepath.Dir(dbPath)
	err = os.MkdirAll(dbDir, 0700)
	require.NoError(t, err)

	file, err := os.Create(dbPath)
	require.NoError(t, err)
	defer file.Close()

	_, err = io.Copy(file, zr)
	require.NoError(t, err)

	metadataFile := filepath.Join(dbDir, "metadata.json")
	b, err := json.Marshal(db.Metadata{
		Version:    1,
		Type:       1,
		NextUpdate: time.Time{},
		UpdatedAt:  time.Time{},
	})
	require.NoError(t, err)

	err = os.WriteFile(metadataFile, b, 0600)
	require.NoError(t, err)

	return tmpDir
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitPort(ctx context.Context, addr string) error {
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil && conn != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		default:
			time.Sleep(1 * time.Second)
		}
	}
}
