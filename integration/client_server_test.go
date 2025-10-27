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

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

type csArgs struct {
	Command             string
	RemoteAddrOption    string
	Format              types.Format
	TemplatePath        string
	IgnoreUnfixed       bool
	Severity            []string
	IgnoreIDs           []string
	Input               string
	ClientToken         string
	ClientTokenHeader   string
	PathPrefix          string
	ListAllPackages     bool
	Target              string
	secretConfig        string
	Distro              string
	VulnSeveritySources []string
}

// TestClientServer tests the client-server mode of Trivy.
//
// Golden files are shared with TestTar or TestRepository.
func TestClientServer(t *testing.T) {
	if *update {
		t.Skipf("Skipping TestClientServer when -update flag is set. Golden files should be updated via TestTar or TestRepository.")
	}

	tests := []struct {
		name     string
		args     csArgs
		golden   string
		override func(t *testing.T, want, got *types.Report)
	}{
		{
			name: "alpine 3.9",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: goldenAlpine39,
		},
		{
			name: "alpine 3.9 as alpine 3.10",
			args: csArgs{
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
				Distro: "alpine/3.10",
			},
			override: func(_ *testing.T, want, _ *types.Report) {
				want.Metadata.OS.Name = "3.10"
				want.Results[0].Target = "testdata/fixtures/images/alpine-39.tar.gz (alpine 3.10)"
			},
			golden: goldenAlpine39,
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
			golden: goldenAlpine39HighCritical,
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
			golden: goldenAlpine39IgnoreCVEIDs,
		},
		{
			name: "alpine 3.10",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: goldenAlpine310JSON,
		},
		{
			name: "alpine distroless",
			args: csArgs{
				Input: "testdata/fixtures/images/alpine-distroless.tar.gz",
			},
			golden: goldenAlpineDistroless,
		},
		{
			name: "debian buster/10",
			args: csArgs{
				Input: "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: goldenDebianBuster,
		},
		{
			name: "debian buster/10 with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: goldenDebianBusterIgnoreUnfixed,
		},
		{
			name: "debian stretch/9",
			args: csArgs{
				Input: "testdata/fixtures/images/debian-stretch.tar.gz",
			},
			golden: goldenDebianStretch,
		},
		{
			name: "ubuntu 18.04",
			args: csArgs{
				Input: "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: goldenUbuntu1804,
		},
		{
			name: "centos 7",
			args: csArgs{
				Input: "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: goldenCentOS7,
		},
		{
			name: "centos 7 with --ignore-unfixed option",
			args: csArgs{
				IgnoreUnfixed: true,
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: goldenCentOS7IgnoreUnfixed,
		},
		{
			name: "centos 7 with medium severity",
			args: csArgs{
				IgnoreUnfixed: true,
				Severity:      []string{"MEDIUM"},
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: goldenCentOS7Medium,
		},
		{
			name: "centos 6",
			args: csArgs{
				Input: "testdata/fixtures/images/centos-6.tar.gz",
			},
			golden: goldenCentOS6,
		},
		{
			name: "ubi 7",
			args: csArgs{
				Input: "testdata/fixtures/images/ubi-7.tar.gz",
			},
			golden: goldenUBI7,
		},
		{
			name: "almalinux 8",
			args: csArgs{
				Input: "testdata/fixtures/images/almalinux-8.tar.gz",
			},
			golden: goldenAlmaLinux8,
		},
		{
			name: "rocky linux 8",
			args: csArgs{
				Input: "testdata/fixtures/images/rockylinux-8.tar.gz",
			},
			golden: goldenRockyLinux8,
		},
		{
			name: "distroless base",
			args: csArgs{
				Input: "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: goldenDistrolessBase,
		},
		{
			name: "distroless python27",
			args: csArgs{
				Input: "testdata/fixtures/images/distroless-python27.tar.gz",
			},
			golden: goldenDistrolessPython27,
		},
		{
			name: "amazon 1",
			args: csArgs{
				Input: "testdata/fixtures/images/amazon-1.tar.gz",
			},
			golden: goldenAmazon1,
		},
		{
			name: "amazon 2",
			args: csArgs{
				Input: "testdata/fixtures/images/amazon-2.tar.gz",
			},
			golden: goldenAmazon2,
		},
		{
			name: "oracle 8",
			args: csArgs{
				Input: "testdata/fixtures/images/oraclelinux-8.tar.gz",
			},
			golden: goldenOracleLinux8,
		},
		{
			name: "opensuse leap 15.1",
			args: csArgs{
				Input: "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			},
			golden: goldenOpenSUSELeap151,
		},
		{
			name: "opensuse tumbleweed",
			args: csArgs{
				Input: "testdata/fixtures/images/opensuse-tumbleweed.tar.gz",
			},
			golden: goldenOpenSUSETumbleweed,
		},
		{
			name: "sle micro rancher 5.4",
			args: csArgs{
				Input: "testdata/fixtures/images/sle-micro-rancher-5.4_ndb.tar.gz",
			},
			golden: goldenSLMicroRancher54,
		},
		{
			name: "photon 3.0",
			args: csArgs{
				Input: "testdata/fixtures/images/photon-30.tar.gz",
			},
			golden: goldenPhoton30,
		},
		{
			name: "CBL-Mariner 1.0",
			args: csArgs{
				Input: "testdata/fixtures/images/mariner-1.0.tar.gz",
			},
			golden: goldenMariner10,
		},
		{
			name: "busybox with Cargo.lock",
			args: csArgs{
				Input: "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			},
			golden: goldenBusyboxWithLockfile,
		},
		{
			name: "scan pox.xml with repo command in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				Target:           "testdata/fixtures/repo/pom/",
			},
			golden: goldenPom,
		},
		{
			name: "scan package-lock.json with repo command in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				Target:           "testdata/fixtures/repo/npm/",
				ListAllPackages:  true,
			},
			golden: goldenNPM,
		},
		{
			name: "scan package-lock.json with severity from `ubuntu` in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				Target:           "testdata/fixtures/repo/npm/",
				VulnSeveritySources: []string{
					"alpine",
					"ubuntu",
				},
			},
			golden: goldenNPMUbuntuSeverity,
		},
		{
			name: "scan sample.pem with repo command in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				secretConfig:     "testdata/fixtures/repo/secrets/trivy-secret.yaml",
				Target:           "testdata/fixtures/repo/secrets/",
			},
			golden: goldenSecrets,
		},
		{
			name: "scan remote repository with repo command in client/server mode",
			args: csArgs{
				Command:          "repo",
				RemoteAddrOption: "--server",
				Target:           "https://github.com/knqyf263/trivy-ci-test",
			},
			golden: goldenTestRepo,
		},
	}

	addr, cacheDir := setup(t, setupOptions{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := setupClient(t, tt.args, addr, cacheDir)

			if tt.args.secretConfig != "" {
				osArgs = append(osArgs, "--secret-config", tt.args.secretConfig)
			}

			runTest(t, osArgs, tt.golden, types.FormatJSON, runOptions{
				override: overrideFuncs(overrideUID, tt.override),
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			})
		})
	}
}

// TestClientServerWithFormat tests the client-server mode with various output formats.
//
// NOTE: Unlike TestClientServer, this test CAN update golden files with the -update flag
// because the golden files used here are not shared with other tests. These format-specific
// golden files (GitLab, SARIF, ASFF, etc.) are unique to this test and should be updated here.
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
			golden: goldenAlpine310GitLab,
		},
		{
			name: "scan package-lock.json with gitlab template (Unknown os and image)",
			args: csArgs{
				Command:         "fs",
				Format:          "template",
				TemplatePath:    "@../contrib/gitlab.tpl",
				Target:          "testdata/fixtures/repo/npm/",
				ListAllPackages: true,
			},
			golden: goldenNPMGitLab,
		},
		{
			name: "alpine 3.10 with gitlab-codequality template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/gitlab-codequality.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: goldenAlpine310GitLabCodeQuality,
		},
		{
			name: "alpine 3.10 with sarif format",
			args: csArgs{
				Format: "sarif",
				Input:  "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: goldenAlpine310SARIF,
		},
		{
			name: "alpine 3.10 with ASFF template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/asff.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: goldenAlpine310ASFF,
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
			golden: goldenSecretsASFF,
		},
		{
			name: "alpine 3.10 with html template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/html.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: goldenAlpine310HTML,
		},
		{
			name: "alpine 3.10 with junit template",
			args: csArgs{
				Format:       "template",
				TemplatePath: "@../contrib/junit.tpl",
				Input:        "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: goldenAlpine310JUnit,
		},
		{
			name: "alpine 3.10 with github dependency snapshots format",
			args: csArgs{
				Format: "github",
				Input:  "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: goldenAlpine310GSBOM,
		},
	}

	fakeTime := time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC)
	report.CustomTemplateFuncMap = map[string]any{
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
		report.CustomTemplateFuncMap = make(map[string]any)
	})

	addr, cacheDir := setup(t, setupOptions{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AWS_REGION", "test-region")
			t.Setenv("AWS_ACCOUNT_ID", "123456789012")
			osArgs := setupClient(t, tt.args, addr, cacheDir)

			runTest(t, osArgs, tt.golden, tt.args.Format, runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: nil, // Do not use overrides - golden files are generated from this test as the canonical source
			})
		})
	}
}

// TestClientServerWithCycloneDX tests the client-server mode with CycloneDX format.
//
// NOTE: This test CAN update golden files with the -update flag because the golden files
// used here are not shared with other tests. These format-specific golden files should be
// updated here.
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
			golden: goldenFluentdMultipleLockfilesCDX,
		},
	}

	addr, cacheDir := setup(t, setupOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := setupClient(t, tt.args, addr, cacheDir)
			runTest(t, osArgs, tt.golden, types.FormatCycloneDX, runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: nil, // Do not use overrides - golden files are generated from this test as the canonical source
			})
		})
	}
}

// TestClientServerWithCustomOptions tests the client-server mode with custom options.
//
// Golden files are shared with TestTar or TestRepository.
func TestClientServerWithCustomOptions(t *testing.T) {
	if *update {
		t.Skipf("Skipping TestClientServerWithCustomOptions when -update flag is set. Golden files should be updated via TestTar or TestRepository.")
	}

	token := "token"
	tokenHeader := "Trivy-Token"
	pathPrefix := "prefix"

	tests := []struct {
		name    string
		args    csArgs
		golden  string
		wantErr string
	}{
		{
			name: "alpine 3.9 with token and prefix",
			args: csArgs{
				Input:             "testdata/fixtures/images/alpine-39.tar.gz",
				ClientToken:       token,
				ClientTokenHeader: tokenHeader,
				PathPrefix:        pathPrefix,
			},
			golden: goldenAlpine39,
		},
		{
			name: "invalid token",
			args: csArgs{
				Input:             "testdata/fixtures/images/distroless-base.tar.gz",
				ClientToken:       "invalidtoken",
				ClientTokenHeader: tokenHeader,
				PathPrefix:        pathPrefix,
			},
			wantErr: "twirp error unauthenticated: invalid token",
		},
		{
			name: "invalid token header",
			args: csArgs{
				Input:             "testdata/fixtures/images/distroless-base.tar.gz",
				ClientToken:       token,
				ClientTokenHeader: "Unknown-Header",
				PathPrefix:        pathPrefix,
			},
			wantErr: "twirp error unauthenticated: invalid token",
		},
		{
			name: "wrong path prefix",
			args: csArgs{
				Input:             "testdata/fixtures/images/distroless-base.tar.gz",
				ClientToken:       token,
				ClientTokenHeader: tokenHeader,
				PathPrefix:        "wrong",
			},
			wantErr: "HTTP status code 404",
		},
	}

	addr, cacheDir := setup(t, setupOptions{
		token:       token,
		tokenHeader: tokenHeader,
		pathPrefix:  pathPrefix,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := setupClient(t, tt.args, addr, cacheDir)
			runTest(t, osArgs, tt.golden, types.FormatJSON, runOptions{
				override: overrideUID,
				wantErr:  tt.wantErr,
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			})
		})
	}
}

// TestClientServerWithRedis tests the client-server mode with Redis cache backend.
//
// Golden files are shared with TestTar or TestRepository.
func TestClientServerWithRedis(t *testing.T) {
	if *update {
		t.Skipf("Skipping TestClientServerWithRedis when -update flag is set. Golden files should be updated via TestTar or TestRepository.")
	}

	// Set up a Redis container
	ctx := t.Context()
	// This test includes 2 checks
	// redisC container will terminate after first check
	redisC, addr := setupRedis(t, ctx)

	// Set up Trivy server
	addr, cacheDir := setup(t, setupOptions{cacheBackend: addr})
	t.Cleanup(func() { os.RemoveAll(cacheDir) })

	// Test parameters
	testArgs := csArgs{
		Input: "testdata/fixtures/images/alpine-39.tar.gz",
	}
	golden := goldenAlpine39

	t.Run("alpine 3.9", func(t *testing.T) {
		osArgs := setupClient(t, testArgs, addr, cacheDir)

		// Run Trivy client
		runTest(t, osArgs, golden, types.FormatJSON, runOptions{
			override: overrideUID,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
		})
	})

	// Terminate the Redis container
	require.NoError(t, testcontainers.TerminateContainer(redisC))

	t.Run("sad path", func(t *testing.T) {
		osArgs := setupClient(t, testArgs, addr, cacheDir)

		// Run Trivy client
		runTest(t, osArgs, "", types.FormatJSON, runOptions{
			wantErr: "unable to store cache",
		})
	})
}

type setupOptions struct {
	token        string
	tokenHeader  string
	pathPrefix   string
	cacheBackend string
}

func setup(t *testing.T, options setupOptions) (string, string) {
	t.Helper()

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	port, err := getFreePort()
	require.NoError(t, err)
	addr := fmt.Sprintf("localhost:%d", port)

	go func() {
		osArgs := setupServer(addr, options.token, options.tokenHeader, options.pathPrefix, cacheDir, options.cacheBackend)

		// Run Trivy server
		assert.NoError(t, execute(osArgs))
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err = waitPort(ctx, addr)
	require.NoError(t, err)

	return addr, cacheDir
}

func setupServer(addr, token, tokenHeader, pathPrefix, cacheDir, cacheBackend string) []string {
	osArgs := []string{
		"--cache-dir",
		cacheDir,
		"server",
		"--skip-db-update",
		"--listen",
		addr,
	}
	if token != "" {
		osArgs = append(osArgs, "--token", token, "--token-header", tokenHeader)
	}
	if pathPrefix != "" {
		osArgs = append(osArgs, "--path-prefix", pathPrefix)
	}
	if cacheBackend != "" {
		osArgs = append(osArgs, "--cache-backend", cacheBackend)
	}
	return osArgs
}

func setupClient(t *testing.T, c csArgs, addr, cacheDir string) []string {
	t.Helper()
	if c.Command == "" {
		c.Command = "image"
	}
	if c.RemoteAddrOption == "" {
		c.RemoteAddrOption = "--server"
	}
	osArgs := []string{
		"--cache-dir",
		cacheDir,
		c.Command,
		c.RemoteAddrOption,
		"http://" + addr,
		"--quiet",
	}

	if c.Format != "" {
		osArgs = append(osArgs, "--format", string(c.Format))
		if c.TemplatePath != "" {
			osArgs = append(osArgs, "--template", c.TemplatePath)
		}
	} else {
		osArgs = append(osArgs, "--format", "json")
	}

	if !c.ListAllPackages {
		osArgs = append(osArgs, "--list-all-pkgs=false")
	}

	if c.IgnoreUnfixed {
		osArgs = append(osArgs, "--ignore-unfixed")
	}
	if len(c.Severity) != 0 {
		osArgs = append(osArgs,
			"--severity", strings.Join(c.Severity, ","),
		)
	}

	if len(c.VulnSeveritySources) != 0 {
		osArgs = append(osArgs,
			"--vuln-severity-source", strings.Join(c.VulnSeveritySources, ","),
		)
	}

	if len(c.IgnoreIDs) != 0 {
		trivyIgnore := filepath.Join(t.TempDir(), ".trivyignore")
		err := os.WriteFile(trivyIgnore, []byte(strings.Join(c.IgnoreIDs, "\n")), 0o444)
		require.NoError(t, err, "failed to write .trivyignore")
		osArgs = append(osArgs, "--ignorefile", trivyIgnore)
	}
	if c.ClientToken != "" {
		osArgs = append(osArgs, "--token", c.ClientToken, "--token-header", c.ClientTokenHeader)
	}
	if c.PathPrefix != "" {
		osArgs = append(osArgs, "--path-prefix", c.PathPrefix)
	}
	if c.Input != "" {
		osArgs = append(osArgs, "--input", c.Input)
	}

	if c.Target != "" {
		osArgs = append(osArgs, c.Target)
	}

	if c.Distro != "" {
		osArgs = append(osArgs, "--distro", c.Distro)
	}

	return osArgs
}

func setupRedis(t *testing.T, ctx context.Context) (testcontainers.Container, string) {
	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	t.Helper()
	imageName := "redis:5.0"
	port := "6379/tcp"
	req := testcontainers.ContainerRequest{
		Name:         "redis",
		Image:        imageName,
		ExposedPorts: []string{port},
		HostConfigModifier: func(hostConfig *dockercontainer.HostConfig) {
			hostConfig.AutoRemove = true
		},
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
