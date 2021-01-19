package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"
)

var (
	inspectURL = "http://podman/images/%s/json"
	saveURL    = "http://podman/images/%s/get"
)

type podmanClient struct {
	c http.Client
}

func newPodmanClient() (podmanClient, error) {
	// Get Podman socket location
	sockDir := os.Getenv("XDG_RUNTIME_DIR")
	socket := filepath.Join(sockDir, "podman", "podman.sock")

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

func (p podmanClient) imageInspect(imageName string) (types.ImageInspect, error) {
	url := fmt.Sprintf(inspectURL, imageName)
	resp, err := p.c.Get(url)
	if err != nil {
		return types.ImageInspect{}, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res errResponse
		if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return types.ImageInspect{}, xerrors.Errorf("unknown status code from Podman: %d", resp.StatusCode)
		}
		return types.ImageInspect{}, xerrors.New(res.Message)
	}

	var inspect types.ImageInspect
	if err = json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return types.ImageInspect{}, xerrors.Errorf("unable to decode JSON: %w", err)
	}
	return inspect, nil
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

// Image implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func PodmanImage(ref string) (v1.Image, *types.ImageInspect, func(), error) {
	cleanup := func() {}

	c, err := newPodmanClient()
	if err != nil {
		return nil, nil, cleanup, xerrors.Errorf("unable to initialize Podman client: %w", err)
	}
	inspect, err := c.imageInspect(ref)
	if err != nil {
		return nil, nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", ref, err)
	}

	f, err := ioutil.TempFile("", "fanal-*")
	if err != nil {
		return nil, nil, cleanup, xerrors.Errorf("failed to create a temporary file")
	}

	cleanup = func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(ref, f, c.imageSave),
		inspect: inspect,
	}, &inspect, cleanup, nil
}
