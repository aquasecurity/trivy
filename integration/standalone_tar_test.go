// +build integration

package integration

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/commands"
)

func TestRun_WithTar(t *testing.T) {
	type args struct {
		Version             string
		WithImageSubcommand bool
		SkipUpdate          bool
		IgnoreUnfixed       bool
		Severity            []string
		IgnoreIDs           []string
		Format              string
		Input               string
		SkipDirs            []string
		SkipFiles           []string
	}
	cases := []struct {
		name     string
		testArgs args
		golden   string
	}{
		{
			name: "alpine 3.10 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name: "alpine 3.10 integration with image subcommand",
			testArgs: args{
				Version:             "dev",
				WithImageSubcommand: true,
				SkipUpdate:          true,
				Format:              "json",
				Input:               "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name: "alpine 3.10 integration with --ignore-unfixed option",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310-ignore-unfixed.json.golden",
		},
		{
			name: "alpine 3.10 integration with medium and high severity",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Severity:      []string{"MEDIUM", "HIGH"},
				Format:        "json",
				Input:         "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310-medium-high.json.golden",
		},
		{
			name: "alpine 3.10 integration with .trivyignore",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: false,
				IgnoreIDs:     []string{"CVE-2019-1549", "CVE-2019-1563"},
				Format:        "json",
				Input:         "testdata/fixtures/images/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310-ignore-cveids.json.golden",
		},
		{
			name: "alpine 3.9 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39.json.golden",
		},
		{
			name: "debian buster integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster.json.golden",
		},
		{
			name: "debian buster integration with --ignore-unfixed option",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name: "debian stretch integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/debian-stretch.tar.gz",
			},
			golden: "testdata/debian-stretch.json.golden",
		},
		{
			name: "ubuntu 18.04 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804.json.golden",
		},
		{
			name: "ubuntu 18.04 integration with --ignore-unfixed option",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name: "ubuntu 16.04 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/ubuntu-1604.tar.gz",
			},
			golden: "testdata/ubuntu-1604.json.golden",
		},
		{
			name: "centos 7 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7.json.golden",
		},
		{
			name: "centos 7 integration with --ignore-unfixed option",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7 integration with low and high severity",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Severity:      []string{"LOW", "HIGH"},
				Format:        "json",
				Input:         "testdata/fixtures/images/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-low-high.json.golden",
		},
		{
			name: "centos 6 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/centos-6.tar.gz",
			},
			golden: "testdata/centos-6.json.golden",
		},
		{
			name: "ubi 7 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/ubi-7.tar.gz",
			},
			golden: "testdata/ubi-7.json.golden",
		},
		{
			name: "distroless base integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base.json.golden",
		},
		{
			name: "distroless base integration with --ignore-unfixed option",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base-ignore-unfixed.json.golden",
		},
		{
			name: "distroless python27 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/distroless-python27.tar.gz",
			},
			golden: "testdata/distroless-python27.json.golden",
		},
		{
			name: "amazon 1 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/amazon-1.tar.gz",
			},
			golden: "testdata/amazon-1.json.golden",
		},
		{
			name: "amazon 2 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/amazon-2.tar.gz",
			},
			golden: "testdata/amazon-2.json.golden",
		},
		{
			name: "oracle 6 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/oraclelinux-6-slim.tar.gz",
			},
			golden: "testdata/oraclelinux-6-slim.json.golden",
		},
		{
			name: "oracle 7 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/oraclelinux-7-slim.tar.gz",
			},
			golden: "testdata/oraclelinux-7-slim.json.golden",
		},
		{
			name: "oracle 8 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/oraclelinux-8-slim.tar.gz",
			},
			golden: "testdata/oraclelinux-8-slim.json.golden",
		},
		{
			name: "opensuse leap 15.1 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			},
			golden: "testdata/opensuse-leap-151.json.golden",
		},
		{
			name: "opensuse leap 42.3 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/opensuse-leap-423.tar.gz",
			},
			golden: "testdata/opensuse-leap-423.json.golden",
		},
		{
			name: "photon 1.0 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/photon-10.tar.gz",
			},
			golden: "testdata/photon-10.json.golden",
		},
		{
			name: "photon 2.0 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/photon-20.tar.gz",
			},
			golden: "testdata/photon-20.json.golden",
		},
		{
			name: "photon 3.0 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/photon-30.tar.gz",
			},
			golden: "testdata/photon-30.json.golden",
		},
		{
			name: "buxybox with Cargo.lock integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			},
			golden: "testdata/busybox-with-lockfile.json.golden",
		},
		{
			name: "fluentd with multiple lock files",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Format:        "json",
				Input:         "testdata/fixtures/images/fluentd-multiple-lockfiles.tar.gz",
				SkipFiles:     []string{"/Gemfile.lock"},
				SkipDirs: []string{
					"/var/lib/gems/2.5.0/gems/http_parser.rb-0.6.0",
					"/var/lib/gems/2.5.0/gems/fluent-plugin-detect-exceptions-0.0.13",
				},
			},
			golden: "testdata/fluentd-multiple-lockfiles.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := gunzipDB(t)

	// Setup CLI App
	app := commands.NewApp("dev")
	app.Writer = ioutil.Discard

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			osArgs := []string{"trivy"}
			osArgs = append(osArgs, "--cache-dir", cacheDir)
			if c.testArgs.WithImageSubcommand {
				osArgs = append(osArgs, "image")
			}
			osArgs = append(osArgs, "--format", c.testArgs.Format)

			if c.testArgs.SkipUpdate {
				osArgs = append(osArgs, "--skip-update")
			}
			if c.testArgs.IgnoreUnfixed {
				osArgs = append(osArgs, "--ignore-unfixed")
			}
			if len(c.testArgs.Severity) != 0 {
				osArgs = append(osArgs,
					[]string{"--severity", strings.Join(c.testArgs.Severity, ",")}...,
				)
			}
			if len(c.testArgs.IgnoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err := ioutil.WriteFile(trivyIgnore, []byte(strings.Join(c.testArgs.IgnoreIDs, "\n")), 0444)
				assert.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}
			if c.testArgs.Input != "" {
				osArgs = append(osArgs, "--input", c.testArgs.Input)
			}

			if len(c.testArgs.SkipFiles) != 0 {
				for _, skipFile := range c.testArgs.SkipFiles {
					osArgs = append(osArgs, "--skip-files", skipFile)
				}
			}

			if len(c.testArgs.SkipDirs) != 0 {
				for _, skipDir := range c.testArgs.SkipDirs {
					osArgs = append(osArgs, "--skip-dirs", skipDir)
				}
			}

			// Setup the output file
			var outputFile string
			if *update {
				outputFile = c.golden
			} else {
				output, _ := ioutil.TempFile("", "integration")
				assert.Nil(t, output.Close())
				defer os.Remove(output.Name())
				outputFile = output.Name()
			}

			osArgs = append(osArgs, []string{"--output", outputFile}...)

			// Run Trivy
			assert.Nil(t, app.Run(osArgs))

			// Compare want and got
			want, err := ioutil.ReadFile(c.golden)
			assert.NoError(t, err)
			got, err := ioutil.ReadFile(outputFile)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))
		})
	}
}
