package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"

	"github.com/docker/docker/api/types"
	apiregistry "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
)

type RegistryConfig struct {
	URL      *url.URL
	Username string
	Password string
}

func (c RegistryConfig) GetAuthConfig() apiregistry.AuthConfig {
	return apiregistry.AuthConfig{
		Username:      c.Username,
		Password:      c.Password,
		ServerAddress: c.URL.Host,
	}
}

func (c RegistryConfig) GetRegistryAuth() (string, error) {
	authConfig := apiregistry.AuthConfig{
		Username: c.Username,
		Password: c.Password,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encodedJSON), nil
}

func (c RegistryConfig) GetBasicAuthorization() string {
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Username, c.Password))))
}

type Docker struct {
	cli *client.Client
}

func New() (Docker, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return Docker{}, err
	}
	return Docker{
		cli: cli,
	}, nil
}

func (d Docker) Login(conf RegistryConfig) error {
	auth := conf.GetAuthConfig()
	return exec.Command("docker", "login", "-u", auth.Username, "-p", auth.Password, auth.ServerAddress).Run()
}

func (d Docker) Logout(conf RegistryConfig) error {
	auth := conf.GetAuthConfig()
	return exec.Command("docker", "logout", auth.ServerAddress).Run()
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
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
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

	if _, err = io.Copy(io.Discard, pushOut); err != nil {
		return err
	}
	return nil
}
