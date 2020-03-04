// +build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/fanal/analyzer"
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
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name                 string
	imageName            string
	imageFile            string
	expectedOS           types.OS
	expectedPkgsFromCmds string
	expectedLibraries    string
}

var testCases = []testCase{
	{
		name:       "happy path, alpine:3.10",
		imageName:  "alpine:3.10",
		imageFile:  "testdata/fixtures/alpine-310.tar.gz",
		expectedOS: types.OS{Name: "3.10.2", Family: "alpine"},
	},
	{
		name:       "happy path, debian:buster",
		imageName:  "debian:buster",
		imageFile:  "testdata/fixtures/debian-buster.tar.gz",
		expectedOS: types.OS{Name: "10.1", Family: "debian"},
	},
	{
		name:       "happy path, ubuntu:18.04",
		imageName:  "ubuntu:18.04",
		imageFile:  "testdata/fixtures/ubuntu-1804.tar.gz",
		expectedOS: types.OS{Name: "18.04", Family: "ubuntu"},
	},
	{
		name:       "happy path, centos6",
		imageName:  "centos:6",
		imageFile:  "testdata/fixtures/centos-6.tar.gz",
		expectedOS: types.OS{Name: "6.10", Family: "centos"},
	},
	{
		name:       "happy path, registry.redhat.io/ubi7",
		imageName:  "registry.redhat.io/ubi7",
		imageFile:  "testdata/fixtures/ubi-7.tar.gz",
		expectedOS: types.OS{Name: "7.7", Family: "redhat"},
	},
	{
		name:       "happy path, amazonlinux:2",
		imageName:  "amazonlinux:2",
		imageFile:  "testdata/fixtures/amazon-2.tar.gz",
		expectedOS: types.OS{Name: "2 (Karoo)", Family: "amazon"},
	},
	{
		name:       "happy path, oracle:8",
		imageName:  "oraclelinux:8-slim",
		imageFile:  "testdata/fixtures/oraclelinux-8-slim.tar.gz",
		expectedOS: types.OS{Name: "8.0", Family: "oracle"},
	},
	{
		name:       "happy path, distroless",
		imageName:  "gcr.io/distroless/base:latest",
		imageFile:  "testdata/fixtures/distroless-base.tar.gz",
		expectedOS: types.OS{Name: "9.9", Family: "debian"},
	},
	{
		name:       "happy path, photon:1.0",
		imageName:  "photon:1.0-20190823",
		imageFile:  "testdata/fixtures/photon-10.tar.gz",
		expectedOS: types.OS{Name: "1.0", Family: "photon"},
	},
	{
		name:       "happy path, opensuse leap 15.1",
		imageName:  "opensuse/leap:latest",
		imageFile:  "testdata/fixtures/opensuse-leap-151.tar.gz",
		expectedOS: types.OS{Name: "15.1", Family: "opensuse.leap"},
	},
	{
		name:                 "happy path, vulnimage with lock files",
		imageName:            "knqyf263/vuln-image:1.2.3",
		imageFile:            "testdata/fixtures/vulnimage.tar.gz",
		expectedOS:           types.OS{Name: "3.7.1", Family: "alpine"},
		expectedLibraries:    "testdata/goldens/knqyf263vuln-image1.2.3.expectedlibs.golden",
		expectedPkgsFromCmds: "testdata/goldens/knqyf263vuln-image1.2.3.expectedpkgsfromcmds.golden",
	},
}

func TestFanal_Library_DockerMode(t *testing.T) {
	t.Parallel()
	for _, tc := range testCases {
		tc := tc // save a copy of tc for use in t.Run https://gist.github.com/posener/92a55c4cd441fc5e5e85f27bca008721
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d, _ := ioutil.TempDir("", "TestFanal_Library_")
			defer os.RemoveAll(d)
			c, err := cache.NewFSCache(d)
			require.NoError(t, err)
			opt := types.DockerOption{
				Timeout:  600 * time.Second,
				SkipPing: true,
			}

			cli, err := client.NewClientWithOpts(client.FromEnv)
			require.NoError(t, err, tc.name)

			testfile, err := os.Open(tc.imageFile)
			require.NoError(t, err)

			// load image into docker engine
			resp, err := cli.ImageLoad(ctx, testfile, true)
			require.NoError(t, err, tc.name)
			io.Copy(ioutil.Discard, resp.Body)

			// tag our image to something unique
			err = cli.ImageTag(ctx, tc.imageName, tc.imageFile)
			require.NoError(t, err, tc.name)

			ext, cleanup, err := docker.NewDockerExtractor(ctx, tc.imageFile, opt)
			require.NoError(t, err)
			defer cleanup()

			ac := analyzer.New(ext, c)
			applier := analyzer.NewApplier(c)

			// run tests twice, one without cache and with cache
			for i := 1; i <= 2; i++ {
				runChecks(t, ctx, ac, applier, tc)
			}

			// clear Cache
			require.NoError(t, c.Clear(), tc.name)

			// remove Image
			_, err = cli.ImageRemove(ctx, tc.imageFile, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
			assert.NoError(t, err, tc.name)
			_, err = cli.ImageRemove(ctx, tc.imageName, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
			assert.NoError(t, err, tc.name)

			// clear Cache
			require.NoError(t, c.Clear(), tc.name)
		})
	}
}

func TestFanal_Library_TarMode(t *testing.T) {
	t.Parallel()
	for _, tc := range testCases {
		tc := tc // save a copy of tc for use in t.Run https://gist.github.com/posener/92a55c4cd441fc5e5e85f27bca008721
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d, _ := ioutil.TempDir("", "TestFanal_Library_")
			defer os.RemoveAll(d)

			c, err := cache.NewFSCache(d)
			require.NoError(t, err)

			applier := analyzer.NewApplier(c)

			opt := types.DockerOption{
				Timeout:  600 * time.Second,
				SkipPing: true,
			}

			ext, cleanup, err := docker.NewDockerArchiveExtractor(ctx, tc.imageFile, opt)
			require.NoError(t, err)
			defer cleanup()

			ac := analyzer.New(ext, c)
			runChecks(t, ctx, ac, applier, tc)

			// clear Cache
			require.NoError(t, c.Clear(), tc.name)
		})
	}
}

func runChecks(t *testing.T, ctx context.Context, ac analyzer.Config, applier analyzer.Applier, tc testCase) {
	imageInfo, err := ac.Analyze(ctx)
	require.NoError(t, err, tc.name)
	imageDetail, err := applier.ApplyLayers(imageInfo.ID, imageInfo.LayerIDs)
	require.NoError(t, err, tc.name)
	commonChecks(t, imageDetail, tc)
}

func commonChecks(t *testing.T, detail types.ImageDetail, tc testCase) {
	assert.Equal(t, tc.expectedOS, *detail.OS, tc.name)
	checkPackages(t, detail, tc)
	checkPackageFromCommands(t, detail, tc)
	checkLibraries(detail, t, tc)
}

func checkPackages(t *testing.T, detail types.ImageDetail, tc testCase) {
	r := strings.NewReplacer("/", "-", ":", "-")
	goldenFile := fmt.Sprintf("testdata/goldens/packages/%s.json.golden", r.Replace(tc.imageName))

	data, _ := ioutil.ReadFile(goldenFile)
	var expectedPkgs []types.Package
	err := json.Unmarshal(data, &expectedPkgs)
	require.NoError(t, err)
	assert.ElementsMatch(t, expectedPkgs, detail.Packages, tc.name)
}

func checkLibraries(detail types.ImageDetail, t *testing.T, tc testCase) {
	if tc.expectedLibraries != "" {
		data, _ := ioutil.ReadFile(tc.expectedLibraries)
		var expectedLibraries map[types.FilePath][]godeptypes.Library
		json.Unmarshal(data, &expectedLibraries)
		require.Equal(t, len(expectedLibraries), len(detail.Applications), tc.name)
	} else {
		assert.Nil(t, detail.Applications, tc.name)
	}
}

func checkPackageFromCommands(t *testing.T, detail types.ImageDetail, tc testCase) {
	if tc.expectedPkgsFromCmds != "" {
		data, _ := ioutil.ReadFile(tc.expectedPkgsFromCmds)
		var expectedPkgsFromCmds []types.Package
		json.Unmarshal(data, &expectedPkgsFromCmds)
		assert.ElementsMatch(t, expectedPkgsFromCmds, detail.HistoryPackages, tc.name)
	} else {
		assert.Equal(t, []types.Package(nil), detail.HistoryPackages, tc.name)
	}
}
