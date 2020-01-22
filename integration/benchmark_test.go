// +build performance

package integration

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/photon"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpm"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/types"
	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name      string
	imageName string
	imageFile string
}

var testCases = []testCase{
	{
		name:      "happy path, alpine:3.10",
		imageName: "alpine:3.10",
		imageFile: "testdata/fixtures/alpine-310.tar.gz",
	},
	{
		name:      "happy path, amazonlinux:2",
		imageName: "amazonlinux:2",
		imageFile: "testdata/fixtures/amazon-2.tar.gz",
	},
	{
		name:      "happy path, debian:buster",
		imageName: "debian:buster",
		imageFile: "testdata/fixtures/debian-buster.tar.gz",
	},
	{
		name:      "happy path, photon:1.0",
		imageName: "photon:1.0-20190823",
		imageFile: "testdata/fixtures/photon-10.tar.gz",
	},
	{
		name:      "happy path, registry.redhat.io/ubi7",
		imageName: "registry.redhat.io/ubi7",
		imageFile: "testdata/fixtures/ubi-7.tar.gz",
	},
	{
		name:      "happy path, opensuse leap 15.1",
		imageName: "opensuse/leap:latest",
		imageFile: "testdata/fixtures/opensuse-leap-151.tar.gz",
	},
	{
		name:      "happy path, vulnimage with lock files",
		imageName: "knqyf263/vuln-image:1.2.3",
		imageFile: "testdata/fixtures/vulnimage.tar.gz",
	},
}

func run(ac analyzer.Config, ctx context.Context, tc testCase, b *testing.B) {
	actualFiles, err := ac.Analyze(ctx, tc.imageFile)
	require.NoError(b, err)

	osFound, err := analyzer.GetOS(actualFiles)
	require.NoError(b, err)

	_, err = analyzer.GetPackages(actualFiles)
	require.NoError(b, err)

	_, err = analyzer.GetPackagesFromCommands(osFound, actualFiles)
	require.NoError(b, err)

	_, err = analyzer.GetLibraries(actualFiles)
	require.NoError(b, err)
}

func runChecksBench(b *testing.B, ac analyzer.Config, c cache.Cache, ctx context.Context, tc testCase) {
	for i := 0; i < b.N; i++ {
		run(ac, ctx, tc, b)
		if c != nil {
			c.Clear()
		}
	}
}

func BenchmarkFanal_Library_DockerMode_WithoutCache(b *testing.B) {
	benchCache, _ := ioutil.TempDir("", "BenchmarkFanal_Library_DockerMode_WithoutCache_*")
	defer os.RemoveAll(benchCache)

	for _, tc := range testCases {
		ctx, c, _, ac := setup(b, tc, benchCache)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			runChecksBench(b, ac, c, ctx, tc)
			b.StopTimer()
		})

		teardown(b, tc, context.Background())
	}
}

func BenchmarkFanal_Library_DockerMode_WithCache(b *testing.B) {
	benchCache, _ := ioutil.TempDir("", "BenchmarkFanal_Library_DockerMode_WithCache_*")
	defer os.RemoveAll(benchCache)

	for _, tc := range testCases {
		ctx, _, _, ac := setup(b, tc, benchCache)
		// run once to generate cache
		run(ac, ctx, tc, b)

		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			runChecksBench(b, ac, nil, context.Background(), tc)
			b.StopTimer()
		})

		teardown(b, tc, context.Background())
	}
}

func teardown(b *testing.B, tc testCase, ctx context.Context) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(b, err, tc.name)

	_, err = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	assert.NoError(b, err, tc.name)
}

func setup(b *testing.B, tc testCase, cacheDir string) (context.Context, cache.Cache, *client.Client, analyzer.Config) {
	ctx := context.Background()
	c := cache.Initialize(cacheDir)

	opt := types.DockerOption{
		Timeout:  600 * time.Second,
		SkipPing: true,
	}

	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(b, err, tc.name)

	// ensure image doesnt already exists
	_, _ = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})

	testfile, err := os.Open(tc.imageFile)
	require.NoError(b, err)

	// load image into docker engine
	_, err = cli.ImageLoad(ctx, testfile, true)
	require.NoError(b, err, tc.name)

	// tag our image to something unique
	err = cli.ImageTag(ctx, tc.imageName, tc.imageFile)
	require.NoError(b, err, tc.name)

	ext, err := docker.NewDockerExtractor(opt, c)
	require.NoError(b, err, tc.name)
	ac := analyzer.Config{Extractor: ext}
	return ctx, c, cli, ac
}
