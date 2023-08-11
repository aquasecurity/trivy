//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/all"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	aimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/all"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "modernc.org/sqlite"
)

var update = flag.Bool("update", false, "update golden files")

type testCase struct {
	name                string
	remoteImageName     string
	imageFile           string
	wantOS              types.OS
	wantPkgsFromCmds    string
	wantApplicationFile string
}

var tests = []testCase{
	{
		name:            "happy path, alpine:3.10",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:alpine-310",
		imageFile:       "../../../../integration/testdata/fixtures/images/alpine-310.tar.gz",
		wantOS: types.OS{
			Name:   "3.10.2",
			Family: "alpine",
		},
	},
	{
		name:            "happy path, amazonlinux:2",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:amazon-2",
		imageFile:       "../../../../integration/testdata/fixtures/images/amazon-2.tar.gz",
		wantOS: types.OS{
			Name:   "2 (Karoo)",
			Family: "amazon",
		},
	},
	{
		name:            "happy path, debian:buster",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:debian-buster",
		imageFile:       "../../../../integration/testdata/fixtures/images/debian-buster.tar.gz",
		wantOS: types.OS{
			Name:   "10.1",
			Family: "debian",
		},
	},
	{
		name:            "happy path, photon:3.0",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:photon-30",
		imageFile:       "../../../../integration/testdata/fixtures/images/photon-30.tar.gz",
		wantOS: types.OS{
			Name:   "3.0",
			Family: "photon",
		},
	},
	{
		name:            "happy path, registry.redhat.io/ubi7",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:ubi-7",
		imageFile:       "../../../../integration/testdata/fixtures/images/ubi-7.tar.gz",
		wantOS: types.OS{
			Name:   "7.7",
			Family: "redhat",
		},
	},
	{
		name:            "happy path, opensuse leap 15.1",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:opensuse-leap-151",
		imageFile:       "../../../../integration/testdata/fixtures/images/opensuse-leap-151.tar.gz",
		wantOS: types.OS{
			Name:   "15.1",
			Family: "opensuse.leap",
		},
	},
	{
		// from registry.suse.com/suse/sle15:15.3.17.8.16
		name:            "happy path, suse 15.3 (NDB)",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:suse-15.3_ndb",
		imageFile:       "../../../../integration/testdata/fixtures/images/suse-15.3_ndb.tar.gz",
		wantOS: types.OS{
			Name:   "15.3",
			Family: "suse linux enterprise server",
		},
	},
	{
		name:            "happy path, Fedora 35",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:fedora-35",
		imageFile:       "../../../../integration/testdata/fixtures/images/fedora-35.tar.gz",
		wantOS: types.OS{
			Name:   "35",
			Family: "fedora",
		},
	},
	{
		name:            "happy path, vulnimage with lock files",
		remoteImageName: "ghcr.io/aquasecurity/trivy-test-images:vulnimage",
		imageFile:       "../../../../integration/testdata/fixtures/images/vulnimage.tar.gz",
		wantOS: types.OS{
			Name:   "3.7.1",
			Family: "alpine",
		},
		wantApplicationFile: "testdata/goldens/vuln-image1.2.3.expectedlibs.golden",
		wantPkgsFromCmds:    "testdata/goldens/vuln-image1.2.3.expectedpkgsfromcmds.golden",
	},
}

func TestFanal_Library_DockerLessMode(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d := t.TempDir()

			c, err := cache.NewFSCache(d)
			require.NoError(t, err, tt.name)

			cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			require.NoError(t, err)

			// remove existing Image if any
			_, _ = cli.ImageRemove(ctx, tt.remoteImageName, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})

			// Enable only registry scanning
			img, cleanup, err := image.NewContainerImage(ctx, tt.remoteImageName, types.ImageOptions{
				ImageSources: types.ImageSources{types.RemoteImageSource},
			})
			require.NoError(t, err)
			defer cleanup()

			// don't scan licenses in the test - in parallel it will fail
			ar, err := aimage.NewArtifact(img, c, artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeExecutable,
					analyzer.TypeLicenseFile,
				},
			})
			require.NoError(t, err)

			applier := applier.NewApplier(c)

			// run tests twice, one without cache and with cache
			for i := 1; i <= 2; i++ {
				runChecks(t, ctx, ar, applier, tt)
			}

			// clear Cache
			require.NoError(t, c.Clear())
		})
	}
}

func TestFanal_Library_DockerMode(t *testing.T) {
	// Disable updating golden files because local images don't have compressed layer digests,
	// and updating golden files in this function results in incomplete files.
	if *update {
		t.Skipf("This test creates wrong golden file")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			d := t.TempDir()

			c, err := cache.NewFSCache(d)
			require.NoError(t, err)

			cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			require.NoError(t, err, tt.name)

			testfile, err := os.Open(tt.imageFile)
			require.NoError(t, err)

			// load image into docker engine
			resp, err := cli.ImageLoad(ctx, testfile, true)
			require.NoError(t, err, tt.name)
			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err, tt.name)

			// Enable only dockerd scanning
			img, cleanup, err := image.NewContainerImage(ctx, tt.remoteImageName, types.ImageOptions{
				ImageSources: types.ImageSources{types.DockerImageSource},
			})
			require.NoError(t, err, tt.name)
			defer cleanup()

			ar, err := aimage.NewArtifact(img, c, artifact.Option{
				// disable license checking in the test - in parallel it will fail because of resource requirement
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeExecutable,
					analyzer.TypeLicenseFile,
				},
			})
			require.NoError(t, err)

			applier := applier.NewApplier(c)

			// run tests twice, one without cache and with cache
			for i := 1; i <= 2; i++ {
				runChecks(t, ctx, ar, applier, tt)
			}

			// clear Cache
			require.NoError(t, c.Clear(), tt.name)

			_, _ = cli.ImageRemove(ctx, tt.remoteImageName, dtypes.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
		})
	}
}

func TestFanal_Library_TarMode(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d := t.TempDir()

			c, err := cache.NewFSCache(d)
			require.NoError(t, err)

			img, err := image.NewArchiveImage(tt.imageFile)
			require.NoError(t, err, tt.name)

			ar, err := aimage.NewArtifact(img, c, artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeExecutable,
					analyzer.TypeLicenseFile,
				},
			})
			require.NoError(t, err)

			applier := applier.NewApplier(c)

			runChecks(t, ctx, ar, applier, tt)

			// clear Cache
			require.NoError(t, c.Clear(), tt.name)
		})
	}
}

func runChecks(t *testing.T, ctx context.Context, ar artifact.Artifact, applier applier.Applier, tc testCase) {
	imageInfo, err := ar.Inspect(ctx)
	require.NoError(t, err, tc.name)
	imageDetail, err := applier.ApplyLayers(imageInfo.ID, imageInfo.BlobIDs)
	require.NoError(t, err, tc.name)
	commonChecks(t, imageDetail, tc)
}

func commonChecks(t *testing.T, detail types.ArtifactDetail, tc testCase) {
	assert.Equal(t, tc.wantOS, detail.OS, tc.name)
	checkOSPackages(t, detail, tc)
	checkPackageFromCommands(t, detail, tc)
	checkLangPkgs(detail, t, tc)
}

func checkOSPackages(t *testing.T, detail types.ArtifactDetail, tc testCase) {
	// Sort OS packages for consistency
	sort.Sort(detail.Packages)

	splitted := strings.Split(tc.remoteImageName, ":")
	goldenFile := fmt.Sprintf("testdata/goldens/packages/%s.json.golden", splitted[len(splitted)-1])

	if *update {
		b, err := json.MarshalIndent(detail.Packages, "", "  ")
		require.NoError(t, err)
		err = os.WriteFile(goldenFile, b, 0666)
		require.NoError(t, err)
		return
	}
	data, err := os.ReadFile(goldenFile)
	require.NoError(t, err, tc.name)

	var expectedPkgs []types.Package
	err = json.Unmarshal(data, &expectedPkgs)
	require.NoError(t, err)

	require.Equal(t, len(expectedPkgs), len(detail.Packages), tc.name)
	sort.Slice(expectedPkgs, func(i, j int) bool { return expectedPkgs[i].Name < expectedPkgs[j].Name })
	sort.Sort(detail.Packages)

	for i := 0; i < len(expectedPkgs); i++ {
		require.Equal(t, expectedPkgs[i].Name, detail.Packages[i].Name, tc.name)
		require.Equal(t, expectedPkgs[i].Version, detail.Packages[i].Version, tc.name)
	}
}

func checkLangPkgs(detail types.ArtifactDetail, t *testing.T, tc testCase) {
	if tc.wantApplicationFile != "" {
		// Sort applications for consistency
		sort.Slice(detail.Applications, func(i, j int) bool {
			if detail.Applications[i].Type != detail.Applications[j].Type {
				return detail.Applications[i].Type < detail.Applications[j].Type
			}
			return detail.Applications[i].FilePath < detail.Applications[j].FilePath
		})

		for _, app := range detail.Applications {
			sort.Sort(app.Libraries)
			for i := range app.Libraries {
				sort.Strings(app.Libraries[i].DependsOn)
			}
		}

		// Do not compare layers
		for _, app := range detail.Applications {
			for i := range app.Libraries {
				app.Libraries[i].Layer = types.Layer{}
			}
		}

		if *update {
			b, err := json.MarshalIndent(detail.Applications, "", "  ")
			require.NoError(t, err)
			err = os.WriteFile(tc.wantApplicationFile, b, 0666)
			require.NoError(t, err)
			return
		}

		var wantApps []types.Application
		data, err := os.ReadFile(tc.wantApplicationFile)
		require.NoError(t, err)
		err = json.Unmarshal(data, &wantApps)
		require.NoError(t, err)

		require.Equal(t, wantApps, detail.Applications, tc.name)
	} else {
		assert.Nil(t, detail.Applications, tc.name)
	}
}

func checkPackageFromCommands(t *testing.T, detail types.ArtifactDetail, tc testCase) {
	if tc.wantPkgsFromCmds != "" {
		data, _ := os.ReadFile(tc.wantPkgsFromCmds)
		var expectedPkgsFromCmds []types.Package

		err := json.Unmarshal(data, &expectedPkgsFromCmds)
		require.NoError(t, err)
		assert.ElementsMatch(t, expectedPkgsFromCmds, detail.ImageConfig.Packages, tc.name)
	} else {
		assert.Equal(t, []types.Package(nil), detail.ImageConfig.Packages, tc.name)
	}
}
