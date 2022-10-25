//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTar(t *testing.T) {
	type args struct {
		IgnoreUnfixed bool
		Severity      []string
		IgnoreIDs     []string
		Format        string
		Input         string
		SkipDirs      []string
		SkipFiles     []string
	}
	tests := []struct {
		name     string
		testArgs args
		golden   string
	}{
		{
			name: "alpine 3.9",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39.json.golden",
		},
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
			name: "alpine 3.9 with skip files",
			testArgs: args{
				Format: "json",
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
			testArgs: args{
				IgnoreUnfixed: true,
				Severity:      []string{"HIGH", "CRITICAL"},
				Format:        "json",
				Input:         "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name: "alpine 3.9 with .trivyignore",
			testArgs: args{
				IgnoreUnfixed: false,
				IgnoreIDs:     []string{"CVE-2019-1549", "CVE-2019-14697"},
				Format:        "json",
				Input:         "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39-ignore-cveids.json.golden",
		},
		{
			name: "alpine 3.10",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name: "alpine distroless",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/alpine-distroless.tar.gz",
			},
			golden: "testdata/alpine-distroless.json.golden",
		},
		{
			name: "amazon linux 1",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/amazon-1.tar.gz",
			},
			golden: "testdata/amazon-1.json.golden",
		},
		{
			name: "amazon linux 2",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/amazon-2.tar.gz",
			},
			golden: "testdata/amazon-2.json.golden",
		},
		{
			name: "debian buster/10",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster.json.golden",
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
		{
			name: "debian stretch/9",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/debian-stretch.tar.gz",
			},
			golden: "testdata/debian-stretch.json.golden",
		},
		{
			name: "ubuntu 18.04",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804.json.golden",
		},
		{
			name: "ubuntu 18.04 with --ignore-unfixed option",
			testArgs: args{
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7.json.golden",
		},
		{
			name: "centos 7with --ignore-unfixed option",
			testArgs: args{
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7 with medium severity",
			testArgs: args{
				IgnoreUnfixed: true,
				Severity:      []string{"MEDIUM"},
				Format:        "json",
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-medium.json.golden",
		},
		{
			name: "centos 6",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/centos-6.tar.gz",
			},
			golden: "testdata/centos-6.json.golden",
		},
		{
			name: "ubi 7",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/ubi-7.tar.gz",
			},
			golden: "testdata/ubi-7.json.golden",
		},
		{
			name: "almalinux 8",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/almalinux-8.tar.gz",
			},
			golden: "testdata/almalinux-8.json.golden",
		},
		{
			name: "rocky linux 8",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/rockylinux-8.tar.gz",
			},
			golden: "testdata/rockylinux-8.json.golden",
		},
		{
			name: "distroless base",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base.json.golden",
		},
		{
			name: "distroless python27",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/distroless-python27.tar.gz",
			},
			golden: "testdata/distroless-python27.json.golden",
		},
		{
			name: "oracle linux 8",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/oraclelinux-8.tar.gz",
			},
			golden: "testdata/oraclelinux-8.json.golden",
		},
		{
			name: "opensuse leap 15.1",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			},
			golden: "testdata/opensuse-leap-151.json.golden",
		},
		{
			name: "photon 3.0",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/photon-30.tar.gz",
			},
			golden: "testdata/photon-30.json.golden",
		},
		{
			name: "CBL-Mariner 1.0",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/mariner-1.0.tar.gz",
			},
			golden: "testdata/mariner-1.0.json.golden",
		},
		{
			name: "busybox with Cargo.lock integration",
			testArgs: args{
				Format: "json",
				Input:  "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			},
			golden: "testdata/busybox-with-lockfile.json.golden",
		},
		{
			name: "fluentd with RubyGems",
			testArgs: args{
				IgnoreUnfixed: true,
				Format:        "json",
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
			osArgs := []string{"--cache-dir", cacheDir, "image", "-q", "--format", tt.testArgs.Format, "--skip-update"}

			if tt.testArgs.IgnoreUnfixed {
				osArgs = append(osArgs, "--ignore-unfixed")
			}
			if len(tt.testArgs.Severity) != 0 {
				osArgs = append(osArgs, "--severity", strings.Join(tt.testArgs.Severity, ","))
			}
			if len(tt.testArgs.IgnoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err := os.WriteFile(trivyIgnore, []byte(strings.Join(tt.testArgs.IgnoreIDs, "\n")), 0444)
				assert.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}
			if tt.testArgs.Input != "" {
				osArgs = append(osArgs, "--input", tt.testArgs.Input)
			}

			if len(tt.testArgs.SkipFiles) != 0 {
				for _, skipFile := range tt.testArgs.SkipFiles {
					osArgs = append(osArgs, "--skip-files", skipFile)
				}
			}

			if len(tt.testArgs.SkipDirs) != 0 {
				for _, skipDir := range tt.testArgs.SkipDirs {
					osArgs = append(osArgs, "--skip-dirs", skipDir)
				}
			}

			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			osArgs = append(osArgs, []string{"--output", outputFile}...)

			// Run Trivy
			err := execute(osArgs)
			require.NoError(t, err)

			// Compare want and got
			compareReports(t, tt.golden, outputFile)
		})
	}
}
