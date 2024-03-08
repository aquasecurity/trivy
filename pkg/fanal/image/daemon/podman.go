package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	api "github.com/docker/docker/api/types"
	dimage "github.com/docker/docker/api/types/image"
	"golang.org/x/xerrors"
)

var (
	inspectURL = "http://podman/images/%s/json"
	historyURL = "http://podman/images/%s/history"
	saveURL    = "http://podman/images/%s/get"
)

type podmanClient struct {
	c http.Client
}

func newPodmanClient(host string) (podmanClient, error) {
	// Get Podman socket location
	sockDir := os.Getenv("XDG_RUNTIME_DIR")
	socket := filepath.Join(sockDir, "podman", "podman.sock")
	if host != "" {
		socket = host
	}

	if _, err := os.Stat(socket); err != nil {
		return podmanClient{}, xerrors.Errorf("no podman socket found: %w", err)
	}

	return podmanClient{
		c: http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socket)
				},
			},
		},
	}, nil
}

type errResponse struct {
	Message string
}

func (p podmanClient) imageInspect(imageName string) (api.ImageInspect, error) {
	url := fmt.Sprintf(inspectURL, imageName)
	resp, err := p.c.Get(url)
	if err != nil {
		return api.ImageInspect{}, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res errResponse
		if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return api.ImageInspect{}, xerrors.Errorf("unknown status code from Podman: %d", resp.StatusCode)
		}
		return api.ImageInspect{}, xerrors.New(res.Message)
	}

	var inspect api.ImageInspect
	if err = json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return api.ImageInspect{}, xerrors.Errorf("unable to decode JSON: %w", err)
	}
	return inspect, nil
}

func (p podmanClient) imageHistoryInspect(imageName string) ([]dimage.HistoryResponseItem, error) {
	url := fmt.Sprintf(historyURL, imageName)
	resp, err := p.c.Get(url)
	if err != nil {
		return []dimage.HistoryResponseItem{}, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res errResponse
		if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return []dimage.HistoryResponseItem{}, xerrors.Errorf("unknown status code from Podman: %d", resp.StatusCode)
		}
		return []dimage.HistoryResponseItem{}, xerrors.New(res.Message)
	}

	var history []dimage.HistoryResponseItem
	if err = json.NewDecoder(resp.Body).Decode(&history); err != nil {
		return []dimage.HistoryResponseItem{}, xerrors.Errorf("unable to decode JSON: %w", err)
	}
	return history, nil
}

func (p podmanClient) imageSave(_ context.Context, imageNames []string) (io.ReadCloser, error) {
	if len(imageNames) < 1 {
		return nil, xerrors.Errorf("no specified image")
	}
	url := fmt.Sprintf(saveURL, imageNames[0])
	resp, err := p.c.Get(url)
	if err != nil {
		return nil, xerrors.Errorf("http error: %w", err)
	}
	return resp.Body, nil
}

// PodmanImage implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func PodmanImage(ref, host string) (Image, func(), error) {
	cleanup := func() {}

	c, err := newPodmanClient(host)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to initialize Podman client: %w", err)
	}
	inspect, err := c.imageInspect(ref)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", ref, err)
	}

	history, err := c.imageHistoryInspect(ref)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", ref, err)
	}

	f, err := os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(context.Background(), ref, f, c.imageSave),
		inspect: inspect,
		history: configHistory(history),
	}, cleanup, nil
}
