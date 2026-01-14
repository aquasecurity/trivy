package pro

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	callbackUrlPath = "/callback"
	loginUrlPath    = "/apikeys/cli-login"
)

type callbackServer struct {
	listener         net.Listener
	server           *http.Server
	callbackReceived chan string
	callbackErr      chan error
	successURL       string
	logger           *log.Logger
}

func newCallbackServer(successURL string, logger *log.Logger) (*callbackServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, xerrors.Errorf("failed to create listener: %w", err)
	}

	cs := &callbackServer{
		listener:         listener,
		callbackReceived: make(chan string, 1),
		callbackErr:      make(chan error, 1),
		successURL:       successURL,
		logger:           logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", cs.handleCallback)

	cs.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return cs, nil
}

func (cs *callbackServer) start() {
	go func() {
		if err := cs.server.Serve(cs.listener); err != nil && err != http.ErrServerClosed {
			log.Error("Server error", log.Err(err))
		}
	}()
}

func (cs *callbackServer) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return cs.server.Shutdown(ctx)
}

func (cs *callbackServer) callbackURL() string {
	return fmt.Sprintf("http://%s%s", cs.listener.Addr().String(), callbackUrlPath)
}

func (cs *callbackServer) waitForToken(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", xerrors.New("login canceled")
	case token := <-cs.callbackReceived:
		return token, nil
	case err := <-cs.callbackErr:
		return "", xerrors.Errorf("login failed: %w", err)
	}
}

func (cs *callbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		cs.callbackErr <- xerrors.New("no token received in callback")
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte("Login failed: no token received")); err != nil {
			cs.logger.Error("Failed to write response", log.Err(err))
		}
		return
	}

	cs.callbackReceived <- token
	cs.logger.Info("Token retrieved from Trivy Pro")

	redirectURL := fmt.Sprintf("%s?status=success", cs.successURL)
	cs.logger.Debug("Redirecting to success URL", log.String("url", redirectURL))
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func Login(ctx context.Context, opts flag.Options) (string, error) {
	logger := log.WithPrefix(log.PrefixPro)

	successURL, err := url.JoinPath(opts.ProOptions.AppURL, loginUrlPath)
	if err != nil {
		return "", xerrors.Errorf("failed to join server URL and success path: %w", err)
	}

	cs, err := newCallbackServer(successURL, logger)
	if err != nil {
		return "", xerrors.Errorf("failed to create callback server: %w", err)
	}
	defer cs.shutdown()

	logger.Debug("Starting callback server", log.String("url", cs.callbackURL()))
	cs.start()

	loginUrl, err := url.JoinPath(opts.ProOptions.AppURL, loginUrlPath)
	if err != nil {
		return "", xerrors.Errorf("failed to join server URL and login path: %w", err)
	}

	loginUrl = fmt.Sprintf("%s?callback=%s", loginUrl, cs.callbackURL())

	logger.Debug("Opening browser", log.String("url", loginUrl))
	if err := openBrowser(loginUrl); err != nil {
		return "", xerrors.Errorf("failed to open browser: %w", err)
	}

	return cs.waitForToken(ctx)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return xerrors.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err := cmd.Start(); err != nil {
		return xerrors.Errorf("failed to open browser: %w", err)
	}

	return nil
}
