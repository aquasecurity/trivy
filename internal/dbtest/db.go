package dbtest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	jdb "github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
)

// InitDB initializes testing database.
func InitDB(t *testing.T, fixtureFiles []string) string {
	// Create a temp dir
	cacheDir := t.TempDir()

	dbDir := db.Dir(cacheDir)
	dbPath := trivydb.Path(dbDir)
	err := os.MkdirAll(dbDir, 0o700)
	require.NoError(t, err)

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	require.NoError(t, err)
	require.NoError(t, loader.Load())
	require.NoError(t, loader.Close())

	// Initialize DB
	require.NoError(t, db.Init(dbDir))

	return cacheDir
}

func Close() error {
	return db.Close()
}

// InitWithMetadata initializes a database with optional metadata and DB file creation.
// If meta is empty, no metadata file is created.
// If createDBFile is false, no DB file is created (useful for testing "DB not found" scenarios).
// Returns the dbDir path.
func InitWithMetadata(t *testing.T, meta metadata.Metadata, createDBFile bool) string {
	t.Helper()

	cacheDir := t.TempDir()
	dbDir := db.Dir(cacheDir)

	// Create metadata if provided
	if !lo.IsEmpty(meta) {
		metaClient := metadata.NewClient(dbDir)
		err := metaClient.Update(meta)
		require.NoError(t, err)
	}

	// Create DB file if requested
	if createDBFile {
		// First, create the DB file using trivy-db directly in write mode
		err := trivydb.Init(dbDir)
		require.NoError(t, err)
		require.NoError(t, trivydb.Close())

		// Then open it in read-only mode using our wrapper
		err = db.Init(dbDir)
		require.NoError(t, err)
	}

	return dbDir
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
