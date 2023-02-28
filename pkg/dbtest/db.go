package dbtest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	"github.com/aquasecurity/trivy-db/pkg/db"
	jdb "github.com/aquasecurity/trivy-java-db/pkg/db"
)

// InitDB initializes testing database.
func InitDB(t *testing.T, fixtureFiles []string) string {
	// Create a temp dir
	dir := t.TempDir()

	dbPath := db.Path(dir)
	dbDir := filepath.Dir(dbPath)
	err := os.MkdirAll(dbDir, 0700)
	require.NoError(t, err)

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	require.NoError(t, err)
	require.NoError(t, loader.Load())
	require.NoError(t, loader.Close())

	// Initialize DB
	require.NoError(t, db.Init(dir))

	return dir
}

func Close() error {
	return db.Close()
}

func InitJavaDB(t *testing.T, cacheDir string) {
	dbDir := filepath.Join(cacheDir, "java-db")
	javaDB, err := jdb.New(dbDir)
	require.NoError(t, err)
	err = javaDB.Init()
	require.NoError(t, err)

	meta := jdb.Metadata{
		Version:    jdb.SchemaVersion,
		NextUpdate: time.Now().Add(24 * time.Hour),
		UpdatedAt:  time.Now(),
	}
	metac := jdb.NewMetadata(dbDir)
	err = metac.Update(meta)
	require.NoError(t, err)
}
