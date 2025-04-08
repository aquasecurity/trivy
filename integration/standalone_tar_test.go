//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/stretchr/testify/require"
)

func TestTar(t *testing.T) {
	type args struct {
		IgnoreUnfixed     bool
		Severity          []string
		IgnoreIDs         []string
		Format            types.Format
		Input             string
		SkipDirs          []string
		SkipFiles         []string
		DetectionPriority ftypes.DetectionPriority
		Distro            string
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		override func(t *testing.T, want, got *types.Report)
	}{
		{
			name: "alpine 3.9",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39.json.golden",
		},
		{
			name: "alpine 3.9 with skip dirs",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
				SkipDirs: []string{
					"/etc",
				},
			},
			golden: "testdata/alpine-39-skip.json.golden",
		},
		{
			name: "alpine 3.9 with skip files",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
				SkipFiles: []string{
					"/etc",
					"/etc/TZ",
					"/etc/alpine-release",
					"/etc/apk",
					"/etc/apk/arch",
					"/etc/apk/keys",
					"/etc/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
					"/etc/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
					"/etc/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
					"/etc/apk/protected_paths.d",
					"/etc/apk/repositories",
					"/etc/apk/world",
					"/etc/conf.d",
					"/etc/crontabs",
					"/etc/crontabs/root",
					"/etc/fstab",
					"/etc/group",
					"/etc/hostname",
					"/etc/hosts",
					"/etc/init.d",
					"/etc/inittab",
					"/etc/issue",
					"/etc/logrotate.d",
					"/etc/logrotate.d/acpid",
					"/etc/modprobe.d",
					"/etc/modprobe.d/aliases.conf",
					"/etc/modprobe.d/blacklist.conf",
					"/etc/modprobe.d/i386.conf",
					"/etc/modprobe.d/kms.conf",
					"/etc/modules",
					"/etc/modules-load.d",
					"/etc/motd",
					"/etc/mtab",
					"/etc/network",
					"/etc/network/if-down.d",
					"/etc/network/if-post-down.d",
					"/etc/network/if-post-up.d",
					"/etc/network/if-pre-down.d",
					"/etc/network/if-pre-up.d",
					"/etc/network/if-up.d",
					"/etc/network/if-up.d/dad",
					"/etc/opt",
					"/etc/os-release",
					"/etc/passwd",
					"/etc/periodic",
					"/etc/periodic/15min",
					"/etc/periodic/daily",
					"/etc/periodic/hourly",
					"/etc/periodic/monthly",
					"/etc/periodic/weekly",
					"/etc/profile",
					"/etc/profile.d",
					"/etc/profile.d/color_prompt",
					"/etc/protocols",
					"/etc/securetty",
					"/etc/services",
					"/etc/shadow",
					"/etc/shells",
					"/etc/ssl",
					"/etc/ssl/cert.pem",
					"/etc/ssl/certs",
					"/etc/ssl/ct_log_list.cnf",
					"/etc/ssl/ct_log_list.cnf.dist",
					"/etc/ssl/misc",
					"/etc/ssl/misc/CA.pl",
					"/etc/ssl/misc/tsget",
					"/etc/ssl/misc/tsget.pl",
					"/etc/ssl/openssl.cnf",
					"/etc/ssl/openssl.cnf.dist",
					"/etc/ssl/private",
					"/etc/sysctl.conf",
					"/etc/sysctl.d",
					"/etc/sysctl.d/00-alpine.conf",
					"/etc/udhcpd.conf",
				},
			},
			golden: "testdata/alpine-39-skip.json.golden",
		},
		{
			name: "alpine 3.9 with high and critical severity",
			args: args{
				IgnoreUnfixed: true,
				Severity: []string{
					"HIGH",
					"CRITICAL",
				},
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name: "alpine 3.9 with .trivyignore",
			args: args{
				IgnoreUnfixed: false,
				IgnoreIDs: []string{
					"CVE-2019-1549",
					"CVE-2019-14697",
				},
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39-ignore-cveids.json.golden",
		},
		{
			name: "alpine 3.9 as alpine 3.10",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
				Distro: "alpine/3.10",
			},
			override: func(t *testing.T, want, got *types.Report) {
				want.Metadata.OS.Name = "3.10"
				want.Results[0].Target = "testdata/fixtures/images/alpine-39.tar.gz (alpine 3.10)"
			},
			golden: "testdata/alpine-39.json.golden",
		},
		{
			name: "alpine 3.10",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name: "alpine distroless",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/alpine-distroless.tar.gz",
			},
			golden: "testdata/alpine-distroless.json.golden",
		},
		{
			name: "amazon linux 1",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/amazon-1.tar.gz",
			},
			golden: "testdata/amazon-1.json.golden",
		},
		{
			name: "amazon linux 2",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/amazon-2.tar.gz",
			},
			golden: "testdata/amazon-2.json.golden",
		},
		{
			name: "debian buster/10",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster.json.golden",
		},
		{
			name: "debian buster/10 with --ignore-unfixed option",
			args: args{
				IgnoreUnfixed: true,
				Format:        types.FormatJSON,
				Input:         "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name: "debian stretch/9",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/debian-stretch.tar.gz",
			},
			golden: "testdata/debian-stretch.json.golden",
		},
		{
			name: "ubuntu 18.04",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804.json.golden",
		},
		{
			name: "ubuntu 18.04 with --ignore-unfixed option",
			args: args{
				IgnoreUnfixed: true,
				Format:        types.FormatJSON,
				Input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7.json.golden",
		},
		{
			name: "centos 7 with --ignore-unfixed option",
			args: args{
				IgnoreUnfixed: true,
				Format:        types.FormatJSON,
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7 with medium severity",
			args: args{
				IgnoreUnfixed: true,
				Severity:      []string{"MEDIUM"},
				Format:        types.FormatJSON,
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-medium.json.golden",
		},
		{
			name: "centos 6",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/centos-6.tar.gz",
			},
			golden: "testdata/centos-6.json.golden",
		},
		{
			name: "ubi 7",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/ubi-7.tar.gz",
			},
			golden: "testdata/ubi-7.json.golden",
		},
		{
			name: "ubi 7 with comprehensive priority",
			args: args{
				Format:            types.FormatJSON,
				Input:             "testdata/fixtures/images/ubi-7.tar.gz",
				DetectionPriority: ftypes.PriorityComprehensive,
			},
			golden: "testdata/ubi-7-comprehensive.json.golden",
		},
		{
			name: "almalinux 8",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/almalinux-8.tar.gz",
			},
			golden: "testdata/almalinux-8.json.golden",
		},
		{
			name: "rocky linux 8",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/rockylinux-8.tar.gz",
			},
			golden: "testdata/rockylinux-8.json.golden",
		},
		{
			name: "distroless base",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base.json.golden",
		},
		{
			name: "distroless python27",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/distroless-python27.tar.gz",
			},
			golden: "testdata/distroless-python27.json.golden",
		},
		{
			name: "oracle linux 8",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/oraclelinux-8.tar.gz",
			},
			golden: "testdata/oraclelinux-8.json.golden",
		},
		{
			name: "opensuse leap 15.1",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			},
			golden: "testdata/opensuse-leap-151.json.golden",
		},
		{
			name: "opensuse tumbleweed",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/opensuse-tumbleweed.tar.gz",
			},
			golden: "testdata/opensuse-tumbleweed.json.golden",
		},
		{
			name: "sle micro rancher 5.4",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/sle-micro-rancher-5.4_ndb.tar.gz",
			},
			golden: "testdata/sl-micro-rancher5.4.json.golden",
		},
		{
			name: "photon 3.0",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/photon-30.tar.gz",
			},
			golden: "testdata/photon-30.json.golden",
		},
		{
			name: "CBL-Mariner 1.0",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/mariner-1.0.tar.gz",
			},
			golden: "testdata/mariner-1.0.json.golden",
		},
		{
			name: "busybox with Cargo.lock integration",
			args: args{
				Format: types.FormatJSON,
				Input:  "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			},
			golden: "testdata/busybox-with-lockfile.json.golden",
		},
		{
			name: "fluentd with RubyGems",
			args: args{
				IgnoreUnfixed: true,
				Format:        types.FormatJSON,
				Input:         "testdata/fixtures/images/fluentd-multiple-lockfiles.tar.gz",
			},
			golden: "testdata/fluentd-gems.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"image",
				"-q",
				"--format",
				string(tt.args.Format),
				"--skip-db-update",
			}

			if tt.args.IgnoreUnfixed {
				osArgs = append(osArgs, "--ignore-unfixed")
			}
			if len(tt.args.Severity) != 0 {
				osArgs = append(osArgs, "--severity", strings.Join(tt.args.Severity, ","))
			}
			if len(tt.args.IgnoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err := os.WriteFile(trivyIgnore, []byte(strings.Join(tt.args.IgnoreIDs, "\n")), 0444)
				require.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}
			if tt.args.Input != "" {
				osArgs = append(osArgs, "--input", tt.args.Input)
			}

			if len(tt.args.SkipFiles) != 0 {
				for _, skipFile := range tt.args.SkipFiles {
					osArgs = append(osArgs, "--skip-files", skipFile)
				}
			}

			if len(tt.args.SkipDirs) != 0 {
				for _, skipDir := range tt.args.SkipDirs {
					osArgs = append(osArgs, "--skip-dirs", skipDir)
				}
			}

			if tt.args.DetectionPriority != "" {
				osArgs = append(osArgs, "--detection-priority", string(tt.args.DetectionPriority))
			}

			if tt.args.Distro != "" {
				osArgs = append(osArgs, "--distro", tt.args.Distro)
			}

			// Run Trivy
			runTest(t, osArgs, tt.golden, "", tt.args.Format, runOptions{
				override: overrideFuncs(overrideUID, tt.override),
			})
		})
	}
}

func TestTarWithEnv(t *testing.T) {
	type args struct {
		IgnoreUnfixed bool
		Severity      []string
		Format        string
		Input         string
		SkipDirs      []string
	}
	tests := []struct {
		name     string
		testArgs args
		golden   string
	}{
		{
			name: "alpine 3.9 with skip dirs",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
				SkipDirs: []string{
					"/etc",
				},
			},
			golden: "testdata/alpine-39-skip.json.golden",
		},
		{
			name: "alpine 3.9 with high and critical severity",
			testArgs: args{
				IgnoreUnfixed: true,
				Severity: []string{
					"HIGH",
					"CRITICAL",
				},
				Format: "json",
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name: "debian buster/10 with --ignore-unfixed option",
			testArgs: args{
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster-ignore-unfixed.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRIVY_FORMAT", tt.testArgs.Format)
			t.Setenv("TRIVY_CACHE_DIR", cacheDir)
			t.Setenv("TRIVY_QUIET", "true")
			t.Setenv("TRIVY_SKIP_UPDATE", "true")

			if tt.testArgs.IgnoreUnfixed {
				t.Setenv("TRIVY_IGNORE_UNFIXED", "true")
			}
			if len(tt.testArgs.Severity) != 0 {
				t.Setenv("TRIVY_SEVERITY", strings.Join(tt.testArgs.Severity, ","))
			}
			if tt.testArgs.Input != "" {
				t.Setenv("TRIVY_INPUT", tt.testArgs.Input)
			}

			if len(tt.testArgs.SkipDirs) != 0 {
				t.Setenv("TRIVY_SKIP_DIRS", strings.Join(tt.testArgs.SkipDirs, ","))
			}

			// Run Trivy
			runTest(t, []string{"image"}, tt.golden, "", types.FormatJSON, runOptions{})
		})
	}
}

func TestTarWithConfigFile(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		configFile string
		golden     string
	}{
		{
			name:  "alpine 3.9 with high and critical severity",
			input: "testdata/fixtures/images/alpine-39.tar.gz",
			configFile: `quiet: true
format: json
severity:
 - HIGH
 - CRITICAL
vulnerability:
 type:
   - os
cache:
 dir: /should/be/overwritten
`,
			golden: "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name:  "debian buster/10 with --ignore-unfixed option",
			input: "testdata/fixtures/images/debian-buster.tar.gz",
			configFile: `quiet: true
format: json
vulnerability:
 ignore-unfixed: true
cache:
 dir: /should/be/overwritten
`,
			golden: "testdata/debian-buster-ignore-unfixed.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "trivy.yaml")
			err := os.WriteFile(configPath, []byte(tt.configFile), 0600)
			require.NoError(t, err)

			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"image",
				"--skip-db-update",
				"--config",
				configPath,
				"--input",
				tt.input,
			}

			// Run Trivy
			runTest(t, osArgs, tt.golden, "", types.FormatJSON, runOptions{})
		})
	}
}
