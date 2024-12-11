//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	registryImage = "registry:2.7.0"
	registryPort  = "5443/tcp"

	authImage    = "cesanta/docker_auth:1"
	authPort     = "5001/tcp"
	authUsername = "admin"
	authPassword = "badmin"
)

func setupRegistry(ctx context.Context, baseDir string, authURL *url.URL) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Name:         "registry",
		Image:        registryImage,
		ExposedPorts: []string{registryPort},
		Env: map[string]string{
			"REGISTRY_HTTP_ADDR":                 "0.0.0.0:5443",
			"REGISTRY_HTTP_TLS_CERTIFICATE":      "/certs/cert.pem",
			"REGISTRY_HTTP_TLS_KEY":              "/certs/key.pem",
			"REGISTRY_AUTH":                      "token",
			"REGISTRY_AUTH_TOKEN_REALM":          fmt.Sprintf("%s/auth", authURL),
			"REGISTRY_AUTH_TOKEN_SERVICE":        "registry.docker.io",
			"REGISTRY_AUTH_TOKEN_ISSUER":         "Trivy auth server",
			"REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE": "/certs/cert.pem",
			"REGISTRY_AUTH_TOKEN_AUTOREDIRECT":   "false",
		},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(filepath.Join(baseDir, "data", "certs"), "/certs"),
		),
		HostConfigModifier: func(hostConfig *dockercontainer.HostConfig) {
			hostConfig.AutoRemove = true
		},
		WaitingFor: wait.ForHTTP("v2").WithTLS(true).WithAllowInsecure(true).
			WithStatusCodeMatcher(func(status int) bool {
				return status == http.StatusUnauthorized
			}),
	}

	registryC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	return registryC, err
}

func setupAuthServer(ctx context.Context, baseDir string) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Name:         "docker_auth",
		Image:        authImage,
		ExposedPorts: []string{authPort},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(filepath.Join(baseDir, "data", "auth_config"), "/config"),
			testcontainers.BindMount(filepath.Join(baseDir, "data", "certs"), "/certs"),
		),
		HostConfigModifier: func(hostConfig *dockercontainer.HostConfig) {
			hostConfig.AutoRemove = true
		},
		Cmd: []string{"/config/config.yml"},
	}

	authC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	return authC, err
}

func getURL(ctx context.Context, container testcontainers.Container, exposedPort nat.Port) (*url.URL, error) {
	ip, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}

	port, err := container.MappedPort(ctx, exposedPort)
	if err != nil {
		return nil, err
	}

	urlStr := fmt.Sprintf("https://%s:%s", ip, port.Port())
	return url.Parse(urlStr)
}

type registryOption struct {
	AuthURL       *url.URL
	Username      string
	Password      string
	RegistryToken bool
	AuthLogin     bool
}

func TestRegistry(t *testing.T) {
	ctx := context.Background()

	baseDir, err := filepath.Abs(".")
	require.NoError(t, err)

	// disable Reaper for auth server and registry containers
	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	// set up auth server
	authC, err := setupAuthServer(ctx, baseDir)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, authC)

	authURL, err := getURL(ctx, authC, authPort)
	require.NoError(t, err)

	// set up registry
	registryC, err := setupRegistry(ctx, baseDir, authURL)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, registryC)

	registryURL, err := getURL(ctx, registryC, registryPort)
	require.NoError(t, err)

	auth := &authn.Basic{
		Username: authUsername,
		Password: authPassword,
	}

	tests := []struct {
		name      string
		imageName string
		imageFile string
		os        string
		option    registryOption
		golden    string
		wantErr   string
	}{
		{
			name:      "authenticate with username/password",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/images/alpine-310.tar.gz",
			os:        "alpine 3.10.2",
			option: registryOption{
				Username: authUsername,
				Password: authPassword,
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name:      "authenticate with registry token",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/images/alpine-310.tar.gz",
			os:        "alpine 3.10.2",
			option: registryOption{
				AuthURL:       authURL,
				Username:      authUsername,
				Password:      authPassword,
				RegistryToken: true,
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name:      "authenticate with 'trivy registry login'",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/images/alpine-310.tar.gz",
			os:        "alpine 3.10.2",
			option: registryOption{
				Username:  authUsername,
				Password:  authPassword,
				AuthLogin: true,
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name:      "amazonlinux 2",
			imageName: "amazonlinux:2",
			imageFile: "testdata/fixtures/images/amazon-2.tar.gz",
			os:        "amazon 2 (Karoo)",
			option: registryOption{
				Username: authUsername,
				Password: authPassword,
			},
			golden: "testdata/amazon-2.json.golden",
		},
		{
			name:      "debian buster",
			imageName: "debian:buster",
			imageFile: "testdata/fixtures/images/debian-buster.tar.gz",
			os:        "debian 10.1",
			option: registryOption{
				Username: authUsername,
				Password: authPassword,
			},
			golden: "testdata/debian-buster.json.golden",
		},
		{
			name:      "sad path",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/images/alpine-310.tar.gz",
			wantErr:   "unexpected status code 401 Unauthorized: Auth failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fmt.Sprintf("%s/%s", registryURL.Host, tt.imageName)
			imageRef, err := name.ParseReference(s)
			require.NoError(t, err)

			// Load a test image from the tar file, tag it and push to the test registry.
			err = replicateImage(imageRef, tt.imageFile, auth)
			require.NoError(t, err)

			osArgs, err := scan(t, imageRef, baseDir, tt.option)
			require.NoError(t, err)

			// Run Trivy
			runTest(t, osArgs, tt.golden, "", types.FormatJSON, runOptions{
				wantErr: tt.wantErr,
				override: overrideFuncs(overrideUID, func(t *testing.T, want, got *types.Report) {
					want.ArtifactName = s
					for i := range want.Results {
						want.Results[i].Target = fmt.Sprintf("%s (%s)", s, tt.os)
					}
				}),
			})
		})
	}
}

func scan(t *testing.T, imageRef name.Reference, baseDir string, opt registryOption) ([]string, error) {
	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	// Setup env
	if err := setupEnv(t, imageRef, baseDir, opt); err != nil {
		return nil, err
	}

	osArgs := []string{
		"-q",
		"--cache-dir",
		cacheDir,
		"image",
		"--format",
		"json",
		"--image-src",
		"remote",
		"--skip-db-update",
		imageRef.Name(),
	}

	return osArgs, nil
}

func setupEnv(t *testing.T, imageRef name.Reference, baseDir string, opt registryOption) error {
	t.Setenv("TRIVY_INSECURE", "true")

	if opt.Username != "" && opt.Password != "" {
		switch {
		case opt.RegistryToken:
			// Get a registry token in advance
			token, err := requestRegistryToken(imageRef, baseDir, opt)
			if err != nil {
				return err
			}
			t.Setenv("TRIVY_REGISTRY_TOKEN", token)
		case opt.AuthLogin:
			t.Setenv("DOCKER_CONFIG", t.TempDir())
			err := execute([]string{
				"registry",
				"login",
				"--username",
				opt.Username,
				"--password",
				opt.Password,
				"--insecure",
				imageRef.Context().RegistryStr(),
			})
			if err != nil {
				return err
			}
		default:
			t.Setenv("TRIVY_USERNAME", opt.Username)
			t.Setenv("TRIVY_PASSWORD", opt.Password)
		}
	}
	return nil
}

func requestRegistryToken(imageRef name.Reference, baseDir string, opt registryOption) (string, error) {
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := os.ReadFile(filepath.Join(baseDir, "data", "certs", "cert.pem"))
	if err != nil {
		return "", err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a HTTPS client and supply the created CA pool
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	// Get a registry token
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth", opt.AuthURL), nil)
	if err != nil {
		return "", err
	}

	// Set query parameters
	values := req.URL.Query()
	values.Set("service", "registry.docker.io")
	values.Set("scope", imageRef.Scope("pull"))
	req.URL.RawQuery = values.Encode()

	req.SetBasicAuth(opt.Username, opt.Password)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	type res struct {
		AccessToken string `json:"access_token"`
	}

	var r res
	if err = json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}

	return r.AccessToken, nil
}

// ReplicateImage tags the given imagePath and pushes it to the given dest registry.
func replicateImage(imageRef name.Reference, imagePath string, auth authn.Authenticator) error {
	img, err := tarball.Image(func() (io.ReadCloser, error) {
		b, err := os.ReadFile(imagePath)
		if err != nil {
			return nil, err
		}
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return io.NopCloser(gr), nil
	}, nil)
	if err != nil {
		return err
	}

	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	err = remote.Write(imageRef, img, remote.WithAuth(auth), remote.WithTransport(t))
	if err != nil {
		return err
	}

	return nil
}
