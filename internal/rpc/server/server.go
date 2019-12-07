package server

import (
	"context"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/server/config"
	dbFile "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
	rpc "github.com/aquasecurity/trivy/rpc/detector"
)

func ListenAndServe(addr string, c config.Config) error {
	requestWg := &sync.WaitGroup{}
	dbUpdateWg := &sync.WaitGroup{}

	withWaitGroup := func(base http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Stop processing requests during DB update
			dbUpdateWg.Wait()

			// Wait for all requests to be processed before DB update
			requestWg.Add(1)
			defer requestWg.Done()

			base.ServeHTTP(w, r)

		})
	}

	go updateDBWorker(c.AppVersion, c.CacheDir, dbUpdateWg, requestWg)

	mux := http.NewServeMux()

	osHandler := rpc.NewOSDetectorServer(initializeOspkgServer(), nil)
	mux.Handle(rpc.OSDetectorPathPrefix, withToken(withWaitGroup(osHandler), c.Token))

	libHandler := rpc.NewLibDetectorServer(initializeLibServer(), nil)
	mux.Handle(rpc.LibDetectorPathPrefix, withToken(withWaitGroup(libHandler), c.Token))

	log.Logger.Infof("Listening %s...", addr)

	return http.ListenAndServe(addr, mux)
}

func withToken(base http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get("Trivy-Token") {
			rpc.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

func updateDBWorker(appVersion, cacheDir string, dbUpdateWg, requestWg *sync.WaitGroup) {
	client := dbFile.NewClient()
	ctx := context.Background()

	for {
		time.Sleep(10 * time.Second)
		needsUpdate, err := client.NeedsUpdate(ctx, appVersion, false, false)
		if err != nil {
			log.Logger.Error(err)
			continue
		} else if !needsUpdate {
			continue
		}

		log.Logger.Info("Updating DB...")
		if err = hotUpdateDB(ctx, client, cacheDir, dbUpdateWg, requestWg); err != nil {
			log.Logger.Error("%+v", err)
			continue
		}
	}
}

func hotUpdateDB(ctx context.Context, client dbFile.Client, cacheDir string,
	dbUpdateWg, requestWg *sync.WaitGroup) error {
	tmpDir, err := ioutil.TempDir("", "db")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	if err := client.Download(ctx, tmpDir, false); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}

	log.Logger.Info("Suspending all requests during DB update")
	dbUpdateWg.Add(1)
	defer dbUpdateWg.Done()

	log.Logger.Info("Waiting for all requests to be processed before DB update...")
	requestWg.Wait()

	if err = db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}

	if _, err = utils.CopyFile(db.Path(tmpDir), db.Path(cacheDir)); err != nil {
		return xerrors.Errorf("failed to copy the database file: %w", err)
	}

	log.Logger.Info("Reopening DB...")
	if err = db.Init(cacheDir); err != nil {
		return xerrors.Errorf("failed to open DB: %w", err)
	}

	return nil
}
