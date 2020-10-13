package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/docker/docker/client"

	"github.com/docker/docker/api/types"
)

// RegistryConfig holds the config for docker registry
type RegistryConfig struct {
	URL      *url.URL
	Username string
	Password string
}

// GetAuthConfig returns the docker registry authConfig
func (c RegistryConfig) GetAuthConfig() types.AuthConfig {
	return types.AuthConfig{
		Username:      c.Username,
		Password:      c.Password,
		ServerAddress: c.URL.Host,
	}
}

// GetRegistryAuth returns the json encoded docker registry auth
func (c RegistryConfig) GetRegistryAuth() (string, error) {
	authConfig := types.AuthConfig{
		Username: c.Username,
		Password: c.Password,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encodedJSON), nil
}

// Docker returns docker client
type Docker struct {
	cli *client.Client
}

// New is the factory method to return docker client
func New() (Docker, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return Docker{}, err
	}
	return Docker{
		cli: cli,
	}, nil
}

// ReplicateImage tags the given imagePath and pushes it to the given dest registry.
func (d Docker) ReplicateImage(ctx context.Context, imageRef, imagePath string, dest RegistryConfig) error {
	// remove existing Image if any
	_, _ = d.cli.ImageRemove(ctx, imageRef, types.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})

	testfile, err := os.Open(imagePath)
	if err != nil {
		return err
	}

	// load image into docker engine
	resp, err := d.cli.ImageLoad(ctx, testfile, true)
	if err != nil {
		return err
	}
	if _, err = io.Copy(ioutil.Discard, resp.Body); err != nil {
		return err
	}
	defer resp.Body.Close()

	targetImageRef := fmt.Sprintf("%s/%s", dest.URL.Host, imageRef)

	if err = d.cli.ImageTag(ctx, imageRef, targetImageRef); err != nil {
		return err
	}
	defer func() {
		_, _ = d.cli.ImageRemove(ctx, imageRef, types.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})
		_, _ = d.cli.ImageRemove(ctx, targetImageRef, types.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})
	}()

	auth, err := dest.GetRegistryAuth()
	if err != nil {
		return err
	}

	pushOut, err := d.cli.ImagePush(ctx, targetImageRef, types.ImagePushOptions{RegistryAuth: auth})
	if err != nil {
		return err
	}
	defer pushOut.Close()

	if _, err = io.Copy(ioutil.Discard, pushOut); err != nil {
		return err
	}
	return nil
}
