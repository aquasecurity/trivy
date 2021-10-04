//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/report"
)

type csArgs struct {
	Format            string
	TemplatePath      string
	IgnoreUnfixed     bool
	Severity          []string
	IgnoreIDs         []string
	Input             string
	ClientToken       string
	ClientTokenHeader string
}

func TestClientServer(t *testing.T) {
	tests := []struct {
		name    string
		args    csArgs
		golden  string
		wantErr string
	}{
		{
			name: "alpine 3.10 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name: "alpine 3.10 integration with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310-ignore-unfixed.json.golden",
		},
		{
			name: "alpine 3.10 integration with medium and high severity",
			args: csArgs{
				IgnoreUnfixed: true,
				Severity:      []string{"MEDIUM", "HIGH"},
				Input:         "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310-medium-high.json.golden",
		},
		{
			name: "alpine 3.10 integration with .trivyignore",
			args: csArgs{
				IgnoreUnfixed: false,
				IgnoreIDs:     []string{"CVE-2019-1549", "CVE-2019-1563"},
				Input:         "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310-ignore-cveids.json.golden",
		},
		{
			name: "alpine 3.9 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39.json.golden",
		},
		{
			name: "debian buster integration",
			args: csArgs{
				Input: "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster.json.golden",
		},
		{
			name: "debian buster integration with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name: "debian stretch integration",
			args: csArgs{
				Input: "testdata/fixtures/images/debian-stretch.tar.gz",
			},
			golden: "testdata/debian-stretch.json.golden",
		},
		{
			name: "ubuntu 18.04 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804.json.golden",
		},
		{
			name: "ubuntu 18.04 integration with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name: "ubuntu 16.04 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/ubuntu-1604.tar.gz",
			},
			golden: "testdata/ubuntu-1604.json.golden",
		},
		{
			name: "centos 7 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7.json.golden",
		},
		{
			name: "centos 7 integration with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7 integration with low and high severity",
			args: csArgs{
				IgnoreUnfixed: true,
				Severity:      []string{"LOW", "HIGH"},
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-low-high.json.golden",
		},
		{
			name: "centos 6 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/centos-6.tar.gz",
			},
			golden: "testdata/centos-6.json.golden",
		},
		{
			name: "ubi 7 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/ubi-7.tar.gz",
			},
			golden: "testdata/ubi-7.json.golden",
		},
		{
			name: "distroless base integration",
			args: csArgs{
				Input: "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base.json.golden",
		},
		{
			name: "distroless base integration with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base-ignore-unfixed.json.golden",
		},
		{
			name: "distroless python27 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/distroless-python27.tar.gz",
			},
			golden: "testdata/distroless-python27.json.golden",
		},
		{
			name: "amazon 1 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/amazon-1.tar.gz",
			},
			golden: "testdata/amazon-1.json.golden",
		},
		{
			name: "amazon 2 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/amazon-2.tar.gz",
			},
			golden: "testdata/amazon-2.json.golden",
		},
		{
			name: "oracle 6 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/oraclelinux-6-slim.tar.gz",
			},
			golden: "testdata/oraclelinux-6-slim.json.golden",
		},
		{
			name: "oracle 7 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/oraclelinux-7-slim.tar.gz",
			},
			golden: "testdata/oraclelinux-7-slim.json.golden",
		},
		{
			name: "oracle 8 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/oraclelinux-8-slim.tar.gz",
			},
			golden: "testdata/oraclelinux-8-slim.json.golden",
		},
		{
			name: "opensuse leap 15.1 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			},
			golden: "testdata/opensuse-leap-151.json.golden",
		},
		{
			name: "opensuse leap 42.3 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/opensuse-leap-423.tar.gz",
			},
			golden: "testdata/opensuse-leap-423.json.golden",
		},
		{
			name: "photon 1.0 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/photon-10.tar.gz",
			},
			golden: "testdata/photon-10.json.golden",
		},
		{
			name: "photon 2.0 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/photon-20.tar.gz",
			},
			golden: "testdata/photon-20.json.golden",
		},
		{
			name: "photon 3.0 integration",
			args: csArgs{
				Input: "testdata/fixtures/images/photon-30.tar.gz",
			},
			golden: "testdata/photon-30.json.golden",
		},
		{
			name: "buxybox with Cargo.lock integration",
			args: csArgs{
				Input: "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			},
			golden: "testdata/busybox-with-lockfile.json.golden",
		},
	}

	app, addr, cacheDir := setup(t, setupOptions{})

	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			osArgs, outputFile := setupClient(t, c.args, addr, cacheDir, c.golden)

			// Run Trivy client
			err := app.Run(osArgs)
			require.NoError(t, err)

			compareReports(t, c.golden, outputFile)
		})
	}
}

func TestClientServerWithTemplate(t *testing.T) {
	tests := []struct {
		name   string
		args   csArgs
		golden string
	}{
		{
			name: "alpine 3.10 integration with gitlab template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/gitlab.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.gitlab.golden",
		},
		{
			name: "alpine 3.10 integration with gitlab-codequality template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/gitlab-codequality.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.gitlab-codequality.golden",
		},
		{
			name: "alpine 3.10 integration with sarif template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/sarif.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.sarif.golden",
		},
		{
			name: "alpine 3.10 integration with ASFF template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/asff.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.asff.golden",
		},
		{
			name: "alpine 3.10 integration with html template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/html.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.html.golden",
		},
	}

	app, addr, cacheDir := setup(t, setupOptions{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report.Now = func() time.Time {
				return time.Date(2020, 8, 10, 7, 28, 17, 958601, time.UTC)
			}
			t.Setenv("AWS_REGION", "test-region")
			t.Setenv("AWS_ACCOUNT_ID", "123456789012")
			osArgs, outputFile := setupClient(t, tt.args, addr, cacheDir, tt.golden)

			// Run Trivy client
			err := app.Run(osArgs)
			require.NoError(t, err)

			want, err := os.ReadFile(tt.golden)
			require.NoError(t, err)

			got, err := os.ReadFile(outputFile)
			require.NoError(t, err)

			assert.EqualValues(t, string(want), string(got))
		})
	}
}

func TestClientServerWithToken(t *testing.T) {
	cases := []struct {
		name    string
		args    csArgs
		golden  string
		wantErr string
	}{
		{
			name: "alpine 3.10 integration with token",
			args: csArgs{
				Input:             "testdata/fixtures/images/alpine-310.tar.gz",
				ClientToken:       "token",
				ClientTokenHeader: "Trivy-Token",
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name: "invalid token",
			args: csArgs{
				Input:             "testdata/fixtures/images/distroless-base.tar.gz",
				ClientToken:       "invalidtoken",
				ClientTokenHeader: "Trivy-Token",
			},
			wantErr: "twirp error unauthenticated: invalid token",
		},
		{
			name: "invalid token header",
			args: csArgs{
				Input:             "testdata/fixtures/images/distroless-base.tar.gz",
				ClientToken:       "valid-token",
				ClientTokenHeader: "Trivy-Token",
			},
			wantErr: "twirp error unauthenticated: invalid token",
		},
	}

	serverToken := "token"
	serverTokenHeader := "Trivy-Token"
	app, addr, cacheDir := setup(t, setupOptions{
		token:       serverToken,
		tokenHeader: serverTokenHeader,
	})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			osArgs, outputFile := setupClient(t, c.args, addr, cacheDir, c.golden)

			// Run Trivy client
			err := app.Run(osArgs)

			if c.wantErr != "" {
				require.NotNil(t, err, c.name)
				assert.Contains(t, err.Error(), c.wantErr, c.name)
				return
			} else {
				assert.NoError(t, err, c.name)
			}

			compareReports(t, c.golden, outputFile)
		})
	}
}

func TestClientServerWithRedis(t *testing.T) {
	// Set up a Redis container
	ctx := context.Background()
	redisC, addr := setupRedis(t, ctx)

	// Set up Trivy server
	app, addr, cacheDir := setup(t, setupOptions{cacheBackend: addr})
	defer os.RemoveAll(cacheDir)

	// Test parameters
	testArgs := csArgs{
		Input: "testdata/fixtures/images/centos-7.tar.gz",
	}
	golden := "testdata/centos-7.json.golden"

	t.Run("centos 7", func(t *testing.T) {
		osArgs, outputFile := setupClient(t, testArgs, addr, cacheDir, golden)

		// Run Trivy client
		err := app.Run(osArgs)
		require.NoError(t, err)

		compareReports(t, golden, outputFile)
	})

	// Terminate the Redis container
	require.NoError(t, redisC.Terminate(ctx))

	t.Run("sad path", func(t *testing.T) {
		osArgs, _ := setupClient(t, testArgs, addr, cacheDir, golden)

		// Run Trivy client
		err := app.Run(osArgs)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "connect: connection refused")
	})
}

type setupOptions struct {
	token        string
	tokenHeader  string
	cacheBackend string
}

func setup(t *testing.T, options setupOptions) (*cli.App, string, string) {
	t.Helper()
	version := "dev"

	// Set up testing DB
	cacheDir := gunzipDB(t)

	port, err := getFreePort()
	assert.NoError(t, err)
	addr := fmt.Sprintf("localhost:%d", port)

	go func() {
		// Setup CLI App
		app := commands.NewApp(version)
		app.Writer = io.Discard
		osArgs := setupServer(addr, options.token, options.tokenHeader, cacheDir, options.cacheBackend)

		// Run Trivy server
		app.Run(osArgs)
	}()

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err = waitPort(ctx, addr)
	assert.NoError(t, err)

	// Setup CLI App
	app := commands.NewApp(version)
	app.Writer = io.Discard

	return app, addr, cacheDir
}

func setupServer(addr, token, tokenHeader, cacheDir, cacheBackend string) []string {
	osArgs := []string{"trivy", "--cache-dir", cacheDir, "server", "--skip-update", "--listen", addr}
	if token != "" {
		osArgs = append(osArgs, []string{"--token", token, "--token-header", tokenHeader}...)
	}
	if cacheBackend != "" {
		osArgs = append(osArgs, "--cache-backend", cacheBackend)
	}
	return osArgs
}

func setupClient(t *testing.T, c csArgs, addr string, cacheDir string, golden string) ([]string, string) {
	t.Helper()
	osArgs := []string{"trivy", "--cache-dir", cacheDir, "client", "--remote", "http://" + addr}

	if c.Format != "" {
		osArgs = append(osArgs, "--format", c.Format)
		if c.TemplatePath != "" {
			osArgs = append(osArgs, "--template", c.TemplatePath)
		}
	} else {
		osArgs = append(osArgs, "--format", "json")
	}

	if c.IgnoreUnfixed {
		osArgs = append(osArgs, "--ignore-unfixed")
	}
	if len(c.Severity) != 0 {
		osArgs = append(osArgs,
			[]string{"--severity", strings.Join(c.Severity, ",")}...,
		)
	}

	if len(c.IgnoreIDs) != 0 {
		trivyIgnore := filepath.Join(t.TempDir(), ".trivyignore")
		err := os.WriteFile(trivyIgnore, []byte(strings.Join(c.IgnoreIDs, "\n")), 0444)
		require.NoError(t, err, "failed to write .trivyignore")
		osArgs = append(osArgs, []string{"--ignorefile", trivyIgnore}...)
	}
	if c.ClientToken != "" {
		osArgs = append(osArgs, []string{"--token", c.ClientToken, "--token-header", c.ClientTokenHeader}...)
	}
	if c.Input != "" {
		osArgs = append(osArgs, []string{"--input", c.Input}...)
	}

	// Setup the output file
	outputFile := filepath.Join(t.TempDir(), "output.json")
	if *update {
		outputFile = golden
	}

	osArgs = append(osArgs, []string{"--output", outputFile}...)

	return osArgs, outputFile
}

func setupRedis(t *testing.T, ctx context.Context) (testcontainers.Container, string) {
	t.Helper()
	imageName := "redis:5.0"
	port := "6379/tcp"
	req := testcontainers.ContainerRequest{
		Name:         "redis",
		Image:        imageName,
		ExposedPorts: []string{port},
		SkipReaper:   true,
		AutoRemove:   true,
	}

	redis, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	ip, err := redis.Host(ctx)
	require.NoError(t, err)

	p, err := redis.MappedPort(ctx, nat.Port(port))
	require.NoError(t, err)

	addr := fmt.Sprintf("redis://%s:%s", ip, p.Port())
	return redis, addr
}
