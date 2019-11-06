// +build integration

package integration_test

import (
	"compress/gzip"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg"
)

var update = flag.Bool("update", false, "update golden files")

func gunzipDB() string {
	gz, err := os.Open("testdata/trivy.db.gz")
	if err != nil {
		log.Panic(err)
	}
	zr, err := gzip.NewReader(gz)
	if err != nil {
		log.Panic(err)
	}

	tmpDir, err := ioutil.TempDir("", "integration")
	if err != nil {
		log.Panic(err)
	}
	dbDir := filepath.Join(tmpDir, "db")
	err = os.MkdirAll(dbDir, 0700)
	if err != nil {
		log.Panic(err)
	}

	file, err := os.Create(filepath.Join(dbDir, "trivy.db"))
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()

	_, err = io.Copy(file, zr)
	if err != nil {
		log.Panic(err)
	}
	return tmpDir
}

func TestRun_WithTar(t *testing.T) {
	type args struct {
		Version       string
		SkipUpdate    bool
		IgnoreUnfixed bool
		Severity      []string
		IgnoreIDs     []string
		Format        string
		Input         string
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
				Input:      "testdata/fixtures/alpine-310.tar.gz",
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
				Input:         "testdata/fixtures/alpine-310.tar.gz",
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
				Input:         "testdata/fixtures/alpine-310.tar.gz",
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
				Input:         "testdata/fixtures/alpine-310.tar.gz",
			},
			golden: "testdata/alpine-310-ignore-cveids.json.golden",
		},
		{
			name: "alpine 3.9 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/alpine-39.tar.gz",
			},
			golden: "testdata/alpine-39.json.golden",
		},
		{
			name: "debian buster integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/debian-buster.tar.gz",
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
				Input:         "testdata/fixtures/debian-buster.tar.gz",
			},
			golden: "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name: "debian stretch integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/debian-stretch.tar.gz",
			},
			golden: "testdata/debian-stretch.json.golden",
		},
		{
			name: "ubuntu 18.04 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/ubuntu-1804.tar.gz",
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
				Input:         "testdata/fixtures/ubuntu-1804.tar.gz",
			},
			golden: "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name: "ubuntu 16.04 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/ubuntu-1604.tar.gz",
			},
			golden: "testdata/ubuntu-1604.json.golden",
		},
		{
			name: "centos 7 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/centos-7.tar.gz",
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
				Input:         "testdata/fixtures/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name: "centos 7 integration with critical severity",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Severity:      []string{"CRITICAL"},
				Format:        "json",
				Input:         "testdata/fixtures/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-critical.json.golden",
		},
		{
			name: "centos 7 integration with low and high severity",
			testArgs: args{
				Version:       "dev",
				SkipUpdate:    true,
				IgnoreUnfixed: true,
				Severity:      []string{"LOW", "HIGH"},
				Format:        "json",
				Input:         "testdata/fixtures/centos-7.tar.gz",
			},
			golden: "testdata/centos-7-low-high.json.golden",
		},
		{
			name: "centos 6 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/centos-6.tar.gz",
			},
			golden: "testdata/centos-6.json.golden",
		},
		{
			name: "ubi 7 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/ubi-7.tar.gz",
			},
			golden: "testdata/ubi-7.json.golden",
		},
		{
			name: "distroless base integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/distroless-base.tar.gz",
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
				Input:         "testdata/fixtures/distroless-base.tar.gz",
			},
			golden: "testdata/distroless-base-ignore-unfixed.json.golden",
		},
		{
			name: "distroless python27 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/distroless-python27.tar.gz",
			},
			golden: "testdata/distroless-python27.json.golden",
		},
		{
			name: "amazon 1 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/amazon-1.tar.gz",
			},
			golden: "testdata/amazon-1.json.golden",
		},
		{
			name: "amazon 2 integration",
			testArgs: args{
				Version:    "dev",
				SkipUpdate: true,
				Format:     "json",
				Input:      "testdata/fixtures/amazon-2.tar.gz",
			},
			golden: "testdata/amazon-2.json.golden",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Copy DB file
			cacheDir := gunzipDB()
			defer os.RemoveAll(cacheDir)

			// Setup CLI App
			app := pkg.NewApp(c.testArgs.Version)
			app.Writer = ioutil.Discard

			osArgs := []string{"trivy", "--cache-dir", cacheDir, "--format", c.testArgs.Format}
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
				osArgs = append(osArgs, []string{"--input", c.testArgs.Input}...)
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
