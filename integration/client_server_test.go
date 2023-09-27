//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

type csArgs struct {
	Command           string
	RemoteAddrOption  string
	Format            string
	TemplatePath      string
	IgnoreUnfixed     bool
	Severity          []string
	IgnoreIDs         []string
	Input             string
	ClientToken       string
	ClientTokenHeader string
	ListAllPackages   bool
	Target            string
	secretConfig      string
}

func TestClientServer(t *testing.T) {
	tests := []struct {
		name    string
		args    csArgs
		golden  string
		wantErr string
	}{
		{
			name: "alpine 3.9",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39.json.golden",
		},
		{
			name: "alpine 3.9 with high and critical severity",
			args: csArgs{
				IgnoreUnfixed: true,
				Severity: []string{
					"HIGH",
					"CRITICAL",
				},
				Input: "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name: "alpine 3.9 with .trivyignore",
			args: csArgs{
				IgnoreUnfixed: false,
				IgnoreIDs: []string{
					"CVE-2019-1549",
					"CVE-2019-14697",
				},
				Input: "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39-ignore-cveids.json.golden",
		},
		{
			name: "alpine 3.10",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name: "alpine distroless",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-distroless.tar.gz",
			},
			golden: "testdata/alpine-distroless.json.golden",
		},
		{
			name: "debian buster/10",
			args: csArgs{
				Input: "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster.json.golden",
		},
		{
			name: "debian buster/10 with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name: "debian stretch/9",
			args: csArgs{
				Input: "testdata/fixtures/images/debian-stretch.tar.gz",
			},
			golden: "testdata/debian-stretch.json.golden",
		},
		{
			name: "ubuntu 18.04",
			args: csArgs{
				Input: "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804.json.golden",
		},
		{
			name: "centos 7",
			args: csArgs{
				Input: "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7.json.golden",
		},
		{
			name: "centos 7 with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7 with medium severity",
			args: csArgs{
				IgnoreUnfixed: true,
				Severity:      []string{"MEDIUM"},
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-medium.json.golden",
		},
		{
			name: "centos 6",
			args: csArgs{
				Input: "testdata/fixtures/images/centos-6.tar.gz",
			},
			golden: "testdata/centos-6.json.golden",
		},
		{
			name: "ubi 7",
			args: csArgs{
				Input: "testdata/fixtures/images/ubi-7.tar.gz",
			},
			golden: "testdata/ubi-7.json.golden",
		},
		{
			name: "almalinux 8",
			args: csArgs{
				Input: "testdata/fixtures/images/almalinux-8.tar.gz",
			},
			golden: "testdata/almalinux-8.json.golden",
		},
		{
			name: "rocky linux 8",
			args: csArgs{
				Input: "testdata/fixtures/images/rockylinux-8.tar.gz",
			},
			golden: "testdata/rockylinux-8.json.golden",
		},
		{
			name: "distroless base",
			args: csArgs{
				Input: "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base.json.golden",
		},
		{
			name: "distroless python27",
			args: csArgs{
				Input: "testdata/fixtures/images/distroless-python27.tar.gz",
			},
			golden: "testdata/distroless-python27.json.golden",
		},
		{
			name: "amazon 1",
			args: csArgs{
				Input: "testdata/fixtures/images/amazon-1.tar.gz",
			},
			golden: "testdata/amazon-1.json.golden",
		},
		{
			name: "amazon 2",
			args: csArgs{
				Input: "testdata/fixtures/images/amazon-2.tar.gz",
			},
			golden: "testdata/amazon-2.json.golden",
		},
		{
			name: "oracle 8",
			args: csArgs{
				Input: "testdata/fixtures/images/oraclelinux-8.tar.gz",
			},
			golden: "testdata/oraclelinux-8.json.golden",
		},
		{
			name: "opensuse leap 15.1",
			args: csArgs{
				Input: "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			},
			golden: "testdata/opensuse-leap-151.json.golden",
		},
		{
			name: "photon 3.0",
			args: csArgs{
				Input: "testdata/fixtures/images/photon-30.tar.gz",
			},
			golden: "testdata/photon-30.json.golden",
		},
		{
			name: "CBL-Mariner 1.0",
			args: csArgs{
				Input: "testdata/fixtures/images/mariner-1.0.tar.gz",
			},
			golden: "testdata/mariner-1.0.json.golden",
		},
		{
			name: "busybox with Cargo.lock",
			args: csArgs{
				Input: "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			},
			golden: "testdata/busybox-with-lockfile.json.golden",
		},
		{
			name: "scan pox.xml with repo command in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				Target:           "testdata/fixtures/repo/pom/",
			},
			golden: "testdata/pom.json.golden",
		},
		{
			name: "scan sample.pem with repo command in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				secretConfig:     "testdata/fixtures/repo/secrets/trivy-secret.yaml",
				Target:           "testdata/fixtures/repo/secrets/",
			},
			golden: "testdata/secrets.json.golden",
		},
		{
			name: "scan remote repository with repo command in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				Target:           "https://github.com/knqyf263/trivy-ci-test",
			},
			golden: "testdata/test-repo.json.golden",
		},
	}

	addr, cacheDir := setup(t, setupOptions{})

	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			osArgs, outputFile := setupClient(t, c.args, addr, cacheDir, c.golden)

			if c.args.secretConfig != "" {
				osArgs = append(osArgs, "--secret-config", c.args.secretConfig)
			}

			//
			err := execute(osArgs)
			require.NoError(t, err)

			compareReports(t, c.golden, outputFile, nil)
		})
	}
}

func TestClientServerWithFormat(t *testing.T) {
	tests := []struct {
		name   string
		args   csArgs
		golden string
	}{
		{
			name: "alpine 3.10 with gitlab template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/gitlab.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.gitlab.golden",
		},
		{
			name: "alpine 3.10 with gitlab-codequality template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/gitlab-codequality.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.gitlab-codequality.golden",
		},
		{
			name: "alpine 3.10 with sarif format",
			args: csArgs{
				Format: "sarif",
				Input:  "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.sarif.golden",
		},
		{
			name: "alpine 3.10 with ASFF template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/asff.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.asff.golden",
		},
		{
			name: "scan secrets with ASFF template",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				Format:           "template",
				TemplatePath:     "@../contrib/asff.tpl",
				Target:           "testdata/fixtures/repo/secrets/",
			},
			golden: "testdata/secrets.asff.golden",
		},
		{
			name: "alpine 3.10 with html template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/html.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.html.golden",
		},
		{
			name: "alpine 3.10 with github dependency snapshots format",
			args: csArgs{
				Format: "github",
				Input:  "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.gsbom.golden",
		},
	}

	fakeTime := time.Date(2020, 8, 10, 7, 28, 17, 958601, time.UTC)
	clock.SetFakeTime(t, fakeTime)

	report.CustomTemplateFuncMap = map[string]interface{}{
		"now": func() time.Time {
			return fakeTime
		},
		"date": func(format string, t time.Time) string {
			return t.Format(format)
		},
	}

	// For GitHub Dependency Snapshots
	t.Setenv("GITHUB_REF", "/ref/feature-1")
	t.Setenv("GITHUB_SHA", "39da54a1ff04120a31df8cbc94ce9ede251d21a3")
	t.Setenv("GITHUB_JOB", "integration")
	t.Setenv("GITHUB_RUN_ID", "1910764383")
	t.Setenv("GITHUB_WORKFLOW", "workflow-name")

	t.Cleanup(func() {
		report.CustomTemplateFuncMap = map[string]interface{}{}
	})

	addr, cacheDir := setup(t, setupOptions{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AWS_REGION", "test-region")
			t.Setenv("AWS_ACCOUNT_ID", "123456789012")
			osArgs, outputFile := setupClient(t, tt.args, addr, cacheDir, tt.golden)

			// Run Trivy client
			err := execute(osArgs)
			require.NoError(t, err)

			want, err := os.ReadFile(tt.golden)
			require.NoError(t, err)

			got, err := os.ReadFile(outputFile)
			require.NoError(t, err)

			assert.EqualValues(t, string(want), string(got))
		})
	}
}

func TestClientServerWithCycloneDX(t *testing.T) {
	tests := []struct {
		name   string
		args   csArgs
		golden string
	}{
		{
			name: "fluentd with RubyGems with CycloneDX format",
			args: csArgs{
				Format: "cyclonedx",
				Input:  "testdata/fixtures/images/fluentd-multiple-lockfiles.tar.gz",
			},
			golden: "testdata/fluentd-multiple-lockfiles.cdx.json.golden",
		},
	}

	addr, cacheDir := setup(t, setupOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock.SetFakeTime(t, time.Date(2020, 9, 10, 14, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			osArgs, outputFile := setupClient(t, tt.args, addr, cacheDir, tt.golden)

			// Run Trivy client
			err := execute(osArgs)
			require.NoError(t, err)

			compareCycloneDX(t, tt.golden, outputFile)
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
			name: "alpine 3.9 with token",
			args: csArgs{
				Input:             "testdata/fixtures/images/alpine-39.tar.gz",
				ClientToken:       "token",
				ClientTokenHeader: "Trivy-Token",
			},
			golden: "testdata/alpine-39.json.golden",
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
				ClientToken:       "token",
				ClientTokenHeader: "Unknown-Header",
			},
			wantErr: "twirp error unauthenticated: invalid token",
		},
	}

	serverToken := "token"
	serverTokenHeader := "Trivy-Token"
	addr, cacheDir := setup(t, setupOptions{
		token:       serverToken,
		tokenHeader: serverTokenHeader,
	})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			osArgs, outputFile := setupClient(t, c.args, addr, cacheDir, c.golden)

			// Run Trivy client
			err := execute(osArgs)
			if c.wantErr != "" {
				require.Error(t, err, c.name)
				assert.Contains(t, err.Error(), c.wantErr, c.name)
				return
			}

			require.NoError(t, err, c.name)
			compareReports(t, c.golden, outputFile, nil)
		})
	}
}

func TestClientServerWithRedis(t *testing.T) {
	// Set up a Redis container
	ctx := context.Background()
	redisC, addr := setupRedis(t, ctx)

	// Set up Trivy server
	addr, cacheDir := setup(t, setupOptions{cacheBackend: addr})
	t.Cleanup(func() { os.RemoveAll(cacheDir) })

	// Test parameters
	testArgs := csArgs{
		Input: "testdata/fixtures/images/alpine-39.tar.gz",
	}
	golden := "testdata/alpine-39.json.golden"

	t.Run("alpine 3.9", func(t *testing.T) {
		osArgs, outputFile := setupClient(t, testArgs, addr, cacheDir, golden)

		// Run Trivy client
		err := execute(osArgs)
		require.NoError(t, err)

		compareReports(t, golden, outputFile, nil)
	})

	// Terminate the Redis container
	require.NoError(t, redisC.Terminate(ctx))

	t.Run("sad path", func(t *testing.T) {
		osArgs, _ := setupClient(t, testArgs, addr, cacheDir, golden)

		// Run Trivy client
		err := execute(osArgs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connect: connection refused")
	})
}

type setupOptions struct {
	token        string
	tokenHeader  string
	cacheBackend string
}

func setup(t *testing.T, options setupOptions) (string, string) {
	t.Helper()

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	port, err := getFreePort()
	assert.NoError(t, err)
	addr := fmt.Sprintf("localhost:%d", port)

	go func() {
		osArgs := setupServer(addr, options.token, options.tokenHeader, cacheDir, options.cacheBackend)

		// Run Trivy server
		require.NoError(t, execute(osArgs))
	}()

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err = waitPort(ctx, addr)
	assert.NoError(t, err)

	return addr, cacheDir
}

func setupServer(addr, token, tokenHeader, cacheDir, cacheBackend string) []string {
	osArgs := []string{
		"--cache-dir",
		cacheDir,
		"server",
		"--skip-update",
		"--listen",
		addr,
	}
	if token != "" {
		osArgs = append(osArgs, []string{
			"--token",
			token,
			"--token-header",
			tokenHeader,
		}...)
	}
	if cacheBackend != "" {
		osArgs = append(osArgs, "--cache-backend", cacheBackend)
	}
	return osArgs
}

func setupClient(t *testing.T, c csArgs, addr string, cacheDir string, golden string) ([]string, string) {
	if c.Command == "" {
		c.Command = "image"
	}
	if c.RemoteAddrOption == "" {
		c.RemoteAddrOption = "--server"
	}
	t.Helper()
	osArgs := []string{
		"--cache-dir",
		cacheDir,
		c.Command,
		c.RemoteAddrOption,
		"http://" + addr,
	}

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
			"--severity", strings.Join(c.Severity, ","),
		)
	}

	if len(c.IgnoreIDs) != 0 {
		trivyIgnore := filepath.Join(t.TempDir(), ".trivyignore")
		err := os.WriteFile(trivyIgnore, []byte(strings.Join(c.IgnoreIDs, "\n")), 0444)
		require.NoError(t, err, "failed to write .trivyignore")
		osArgs = append(osArgs, "--ignorefile", trivyIgnore)
	}
	if c.ClientToken != "" {
		osArgs = append(osArgs, "--token", c.ClientToken, "--token-header", c.ClientTokenHeader)
	}
	if c.Input != "" {
		osArgs = append(osArgs, "--input", c.Input)
	}

	// Set up the output file
	outputFile := filepath.Join(t.TempDir(), "output.json")
	if *update {
		outputFile = golden
	}

	osArgs = append(osArgs, "--output", outputFile)

	if c.Target != "" {
		osArgs = append(osArgs, c.Target)
	}

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
