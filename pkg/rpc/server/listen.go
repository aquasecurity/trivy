package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/aquasecurity/trivy/pkg/version"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

const updateInterval = 1 * time.Hour

// Server represents Trivy server
type Server struct {
	appVersion     string
	addr           string
	cacheDir       string
	dbDir          string
	token          string
	tokenHeader    string
	pathPrefix     string
	dbRepositories []name.Reference

	// For OCI registries
	types.RegistryOptions
}

// NewServer returns an instance of Server
func NewServer(appVersion, addr, cacheDir, token, tokenHeader, pathPrefix string, dbRepositories []name.Reference, opt types.RegistryOptions) Server {
	return Server{
		appVersion:      appVersion,
		addr:            addr,
		cacheDir:        cacheDir,
		dbDir:           db.Dir(cacheDir),
		token:           token,
		tokenHeader:     tokenHeader,
		pathPrefix:      pathPrefix,
		dbRepositories:  dbRepositories,
		RegistryOptions: opt,
	}
}

// ListenAndServe starts Trivy server
func (s Server) ListenAndServe(ctx context.Context, serverCache cache.Cache, skipDBUpdate bool) error {
	requestWg := &sync.WaitGroup{}
	dbUpdateWg := &sync.WaitGroup{}

	go func() {
		worker := newDBWorker(db.NewClient(s.dbDir, true, db.WithDBRepository(s.dbRepositories)))
		for {
			time.Sleep(updateInterval)
			if err := worker.update(ctx, s.appVersion, s.dbDir, skipDBUpdate, dbUpdateWg, requestWg, s.RegistryOptions); err != nil {
				log.Errorf("%+v\n", err)
			}
		}
	}()

	mux := s.NewServeMux(ctx, serverCache, dbUpdateWg, requestWg)
	log.Infof("Listening %s...", s.addr)

	return http.ListenAndServe(s.addr, mux)
}

func (s Server) NewServeMux(ctx context.Context, serverCache cache.Cache, dbUpdateWg, requestWg *sync.WaitGroup) *http.ServeMux {
	withWaitGroup := func(base http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Stop processing requests during DB update
			dbUpdateWg.Wait()

			// Wait for all requests to be processed before DB update
			requestWg.Add(1)
			defer requestWg.Done()

			base.ServeHTTP(w, r.WithContext(ctx))

		})
	}

	mux := http.NewServeMux()

	var twirpOpts []any
	if s.pathPrefix != "" {
		pathPrefix := "/" + strings.TrimPrefix(s.pathPrefix, "/") // Twirp requires the leading slash
		twirpOpts = append(twirpOpts, twirp.WithServerPathPrefix(pathPrefix))
	}

	scanServer := rpcScanner.NewScannerServer(initializeScanServer(serverCache), twirpOpts...)
	scanHandler := withToken(withWaitGroup(scanServer), s.token, s.tokenHeader)
	mux.Handle(scanServer.PathPrefix(), gziphandler.GzipHandler(scanHandler))

	cacheServer := rpcCache.NewCacheServer(NewCacheServer(serverCache), twirpOpts...)
	layerHandler := withToken(withWaitGroup(cacheServer), s.token, s.tokenHeader)
	mux.Handle(cacheServer.PathPrefix(), gziphandler.GzipHandler(layerHandler))

	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, r *http.Request) {
		if _, err := rw.Write([]byte("ok")); err != nil {
			log.Error("Health check error", log.Err(err))
		}
	})

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(version.NewVersionInfo(s.cacheDir)); err != nil {
			log.Error("Version error", log.Err(err))
		}
	})

	return mux
}

func withToken(base http.Handler, token, tokenHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get(tokenHeader) {
			rpcScanner.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

type dbWorker struct {
	dbClient *db.Client
}

func newDBWorker(dbClient *db.Client) dbWorker {
	return dbWorker{dbClient: dbClient}
}

func (w dbWorker) update(ctx context.Context, appVersion, dbDir string,
	skipDBUpdate bool, dbUpdateWg, requestWg *sync.WaitGroup, opt types.RegistryOptions) error {
	log.Debug("Check for DB update...")
	needsUpdate, err := w.dbClient.NeedsUpdate(ctx, appVersion, skipDBUpdate)
	if err != nil {
		return xerrors.Errorf("failed to check if db needs an update")
	} else if !needsUpdate {
		return nil
	}

	log.Info("Updating DB...")
	if err = w.hotUpdate(ctx, dbDir, dbUpdateWg, requestWg, opt); err != nil {
		return xerrors.Errorf("failed DB hot update: %w", err)
	}
	return nil
}

func (w dbWorker) hotUpdate(ctx context.Context, dbDir string, dbUpdateWg, requestWg *sync.WaitGroup, opt types.RegistryOptions) error {
	tmpDir, err := os.MkdirTemp("", "db")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err = w.dbClient.Download(ctx, tmpDir, opt); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}

	log.Info("Suspending all requests during DB update")
	dbUpdateWg.Add(1)
	defer dbUpdateWg.Done()

	log.Info("Waiting for all requests to be processed before DB update...")
	requestWg.Wait()

	if err = db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}

	// Copy trivy.db
	if _, err = fsutils.CopyFile(db.Path(tmpDir), db.Path(dbDir)); err != nil {
		return xerrors.Errorf("failed to copy the database file: %w", err)
	}

	// Copy metadata.json
	if _, err = fsutils.CopyFile(metadata.Path(tmpDir), metadata.Path(dbDir)); err != nil {
		return xerrors.Errorf("failed to copy the metadata file: %w", err)
	}

	log.Info("Reopening DB...")
	if err = db.Init(dbDir); err != nil {
		return xerrors.Errorf("failed to open DB: %w", err)
	}

	return nil
}
