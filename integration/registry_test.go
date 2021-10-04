//go:build integration
// +build integration

package integration

import (
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

	"github.com/docker/go-connections/nat"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/aquasecurity/fanal/analyzer"
	testdocker "github.com/aquasecurity/trivy/integration/docker"
	"github.com/aquasecurity/trivy/pkg/commands"
)

const (
	registryImage = "registry:2"
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
		},
		BindMounts: map[string]string{
			filepath.Join(baseDir, "data", "certs"): "/certs",
		},
		SkipReaper: true,
		AutoRemove: true,
		WaitingFor: wait.ForLog("listening on [::]:5443"),
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
		BindMounts: map[string]string{
			filepath.Join(baseDir, "data", "auth_config"): "/config",
			filepath.Join(baseDir, "data", "certs"):       "/certs",
		},
		SkipReaper: true,
		AutoRemove: true,
		Cmd:        []string{"/config/config.yml"},
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
}

func TestRegistry(t *testing.T) {
	ctx := context.Background()

	baseDir, err := filepath.Abs(".")
	require.NoError(t, err)

	// set up auth server
	authC, err := setupAuthServer(ctx, baseDir)
	require.NoError(t, err)
	defer authC.Terminate(ctx)

	authURL, err := getURL(ctx, authC, authPort)
	require.NoError(t, err)

	// set up registry
	registryC, err := setupRegistry(ctx, baseDir, authURL)
	require.NoError(t, err)
	defer registryC.Terminate(ctx)

	registryURL, err := getURL(ctx, registryC, registryPort)
	require.NoError(t, err)

	config := testdocker.RegistryConfig{
		URL:      registryURL,
		Username: authUsername,
		Password: authPassword,
	}

	testCases := []struct {
		name      string
		imageName string
		imageFile string
		option    registryOption
		golden    string
		wantErr   string
	}{
		{
			name:      "happy path with username/password",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/images/alpine-310.tar.gz",
			option: registryOption{
				AuthURL:  authURL,
				Username: authUsername,
				Password: authPassword,
			},
			golden: "testdata/alpine-310-registry.json.golden",
		},
		{
			name:      "happy path with registry token",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/images/alpine-310.tar.gz",
			option: registryOption{
				AuthURL:       authURL,
				Username:      authUsername,
				Password:      authPassword,
				RegistryToken: true,
			},
			golden: "testdata/alpine-310-registry.json.golden",
		},
		{
			name:      "sad path",
			imageName: "alpine:3.10",
			imageFile: "testdata/fixtures/images/alpine-310.tar.gz",
			wantErr:   "unexpected status code 401 Unauthorized: Auth failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := testdocker.New()
			require.NoError(t, err)

			s := fmt.Sprintf("%s/%s", registryURL.Host, tc.imageName)
			imageRef, err := name.ParseReference(s)
			require.NoError(t, err)

			// 1. Load a test image from the tar file, tag it and push to the test registry.
			err = d.ReplicateImage(ctx, tc.imageName, tc.imageFile, config)
			require.NoError(t, err)

			// 2. Scan it
			resultFile, err := scan(t, imageRef, baseDir, tc.golden, tc.option)

			if tc.wantErr != "" {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), tc.wantErr, err)
				return
			} else {
				require.NoError(t, err)
			}

			// 3. Read want and got
			want := readReport(t, tc.golden)
			got := readReport(t, resultFile)

			// 4 Update some dynamic fields
			want.ArtifactName = s
			for i := range want.Results {
				want.Results[i].Target = fmt.Sprintf("%s (alpine 3.10.2)", s)
			}
			want.Metadata.RepoDigests = []string{
				fmt.Sprintf("%s/alpine@sha256:acd3ca9941a85e8ed16515bfc5328e4e2f8c128caa72959a58a127b7801ee01f", registryURL.Host),
			}

			// 5. Compare want and got
			assert.Equal(t, want, got)
		})
	}
}

func scan(t *testing.T, imageRef name.Reference, baseDir, goldenFile string, opt registryOption) (string, error) {
	// Set up testing DB
	cacheDir := gunzipDB(t)

	// Setup the output file
	outputFile := filepath.Join(t.TempDir(), "output.json")
	if *update {
		outputFile = goldenFile
	}

	// Setup env
	if err := setupEnv(t, imageRef, baseDir, opt); err != nil {
		return "", err
	}

	// Setup CLI App
	app := commands.NewApp("dev")
	app.Writer = io.Discard

	osArgs := []string{"trivy", "--cache-dir", cacheDir, "--format", "json", "--skip-update", "--output", outputFile, imageRef.Name()}

	// Run Trivy
	if err := app.Run(osArgs); err != nil {
		return "", err
	}
	return outputFile, nil
}

func setupEnv(t *testing.T, imageRef name.Reference, baseDir string, opt registryOption) error {
	t.Setenv("TRIVY_INSECURE", "true")

	if opt.Username != "" && opt.Password != "" {
		if opt.RegistryToken {
			// Get a registry token in advance
			token, err := requestRegistryToken(imageRef, baseDir, opt)
			if err != nil {
				return err
			}
			t.Setenv("TRIVY_REGISTRY_TOKEN", token)
		} else {
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
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/auth", opt.AuthURL), nil)
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
