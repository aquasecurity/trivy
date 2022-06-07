//go:build performance
// +build performance

package integration

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
	"time"

	_ "github.com/aquasecurity/fanal/analyzer/all"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name      string
	imageName string
	imageFile string
}

var testCases = []testCase{
	{
		name:      "happy path alpine:3.10",
		imageName: "alpine:3.10",
		imageFile: "testdata/fixtures/alpine-310.tar.gz",
	},
	{
		name:      "happy path vulnimage with lock files",
		imageName: "knqyf263/vuln-image:1.2.3",
		imageFile: "testdata/fixtures/vulnimage.tar.gz",
	},
}

func run(b *testing.B, ctx context.Context, imageName string, c cache.Cache, opt types.DockerOption) {
	// TODO: fix
	//_, cleanup, err := docker.NewDockerExtractor(ctx, imageName, opt)
	//require.NoError(b, err)
	//defer cleanup()
	//
	//ac := analyzer.New(ext, c)
	//
	//_, err = ac.Analyze(ctx)
	//require.NoError(b, err)
}

func BenchmarkDockerMode_WithoutCache(b *testing.B) {
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			cacheDir := b.TempDir()

			ctx, imageName, cli := setup(b, tc)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				c, err := cache.NewFSCache(cacheDir)
				require.NoError(b, err)
				b.StartTimer()

				run(b, ctx, imageName, c, types.DockerOption{})

				b.StopTimer()
				_ = c.Clear()
				b.StartTimer()
			}

			b.StopTimer()
			teardown(b, ctx, tc.imageName, imageName, cli)
		})
	}
}

func BenchmarkDockerMode_WithCache(b *testing.B) {
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			cacheDir := b.TempDir()

			ctx, imageName, cli := setup(b, tc)

			c, err := cache.NewFSCache(cacheDir)
			require.NoError(b, err)

			// run once to generate cache
			run(b, ctx, imageName, c, types.DockerOption{})

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				run(b, ctx, imageName, c, types.DockerOption{})
			}
			b.StopTimer()

			teardown(b, ctx, tc.imageName, imageName, cli)
		})

	}
}

func teardown(b *testing.B, ctx context.Context, originalImageName, imageName string, cli *client.Client) {
	_, err := cli.ImageRemove(ctx, originalImageName, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	require.NoError(b, err)

	_, err = cli.ImageRemove(ctx, imageName, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	require.NoError(b, err)
}

func setup(b *testing.B, tc testCase) (context.Context, string, *client.Client) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(b, err, tc.name)

	// ensure image doesnt already exists
	_, _ = cli.ImageRemove(ctx, tc.imageName, dtypes.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	})

	testFile, err := os.Open(tc.imageFile)
	require.NoError(b, err)

	// load image into docker engine
	resp, err := cli.ImageLoad(ctx, testFile, false)
	require.NoError(b, err, tc.name)

	// ensure an image has finished being loaded.
	io.Copy(ioutil.Discard, resp.Body)
	require.NoError(b, resp.Body.Close())

	rs := rand.NewSource(time.Now().UnixNano())
	imageName := fmt.Sprintf("%s-%d", tc.imageName, rand.New(rs).Intn(1000000))

	// tag our image to something unique
	err = cli.ImageTag(ctx, tc.imageName, imageName)
	require.NoError(b, err, tc.name)

	return ctx, imageName, cli
}
