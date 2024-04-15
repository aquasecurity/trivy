package cyclonedx_test

import (
	"encoding/json"
	"github.com/aquasecurity/trivy/pkg/purl"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
)

func TestUnmarshaler_Unmarshal(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      types.SBOM
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:49193a2310dbad4c02382da87ac624a80a92387a4f7536235f9ba590e5bcd7b5",
					DiffIDs: []string{
						"sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
						"sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
					},
					RepoTags: []string{
						"maven-test-project:latest",
					},
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "musl@1.2.3-r0",
								Name:       "musl",
								Version:    "1.2.3-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.3-r0",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.2.3-r0",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "3.16.0",
											},
										},
									},
									BOMRef: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.0",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
								},
							},
						},
					},
				},
				Applications: []ftypes.Application{
					{
						Type:     ftypes.Composer,
						FilePath: "app/composer/composer.lock",
						Libraries: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type:     ftypes.GoBinary,
						FilePath: "app/gobinary/gobinary",
						Libraries: ftypes.Packages{
							{
								ID:      "github.com/package-url/packageurl-go@v0.1.1-0.20220203205134-d70459300c8a",
								Name:    "github.com/package-url/packageurl-go",
								Version: "v0.1.1-0.20220203205134-d70459300c8a",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/package-url",
										Name:      "packageurl-go",
										Version:   "v0.1.1-0.20220203205134-d70459300c8a",
									},
									BOMRef: "pkg:golang/github.com/package-url/packageurl-go@v0.1.1-0.20220203205134-d70459300c8a",
								},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type:     ftypes.Gradle,
						FilePath: "app/gradle/target/gradle.lockfile",
						Libraries: ftypes.Packages{
							{
								ID:   "com.example:example:0.0.1",
								Name: "com.example:example",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "com.example",
										Name:      "example",
										Version:   "0.0.1",
									},
									BOMRef: "pkg:maven/com.example/example@0.0.1",
								},
								Version: "0.0.1",
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
							},
						},
					},
					{
						Type: ftypes.Jar,
						Libraries: ftypes.Packages{
							{
								ID:   "org.codehaus.mojo:child-project:1.0",
								Name: "org.codehaus.mojo:child-project",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.codehaus.mojo",
										Name:      "child-project",
										Version:   "1.0",
									},
									BOMRef: "pkg:maven/org.codehaus.mojo/child-project@1.0?file_path=app%2Fmaven%2Ftarget%2Fchild-project-1.0.jar",
								},
								Version: "1.0",
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
								FilePath: "app/maven/target/child-project-1.0.jar",
							},
						},
					},
					{
						Type:     ftypes.NodePkg,
						FilePath: "",
						Libraries: ftypes.Packages{
							{
								ID:      "@example/bootstrap@5.0.2",
								Name:    "@example/bootstrap",
								Version: "5.0.2",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeNPM,
										Namespace: "@example",
										Name:      "bootstrap",
										Version:   "5.0.2",
									},
									BOMRef: "pkg:npm/@example/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
								},
								Licenses: []string{"MIT"},
								Layer: ftypes.Layer{
									DiffID: "sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
								},
								FilePath: "app/app/package.json",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path KBOM",
			inputFile: "testdata/happy/kbom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "ubuntu",
						Name:   "22.04.2",
					},
				},
				Applications: []ftypes.Application{
					{
						Type: ftypes.GoBinary,
						Libraries: ftypes.Packages{
							{
								ID:      "docker@v24.0.4",
								Name:    "docker",
								Version: "24.0.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeGolang,
										Name:    "docker",
										Version: "24.0.4",
									},
									BOMRef: "pkg:golang/docker@24.0.4",
								},
							},
						},
					},
					{
						Type: ftypes.K8sUpstream,
						Libraries: ftypes.Packages{
							{
								ID:      "k8s.io/apiserver@1.27.4",
								Name:    "k8s.io/apiserver",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/apiserver",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fapiserver@1.27.4",
								},
							},
							{
								ID:      "k8s.io/controller-manager@1.27.4",
								Name:    "k8s.io/controller-manager",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/controller-manager",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fcontroller-manager@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kube-proxy@1.27.4",
								Name:    "k8s.io/kube-proxy",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kube-proxy",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkube-proxy@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kube-scheduler@1.27.4",
								Name:    "k8s.io/kube-scheduler",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kube-scheduler",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkube-scheduler@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kubelet@1.27.4",
								Name:    "k8s.io/kubelet",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kubelet",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkubelet@1.27.4",
								},
							},
							{
								ID:      "k8s.io/kubernetes@1.27.4",
								Name:    "k8s.io/kubernetes",
								Version: "1.27.4",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    purl.TypeK8s,
										Name:    "k8s.io/kubernetes",
										Version: "1.27.4",
									},
									BOMRef: "pkg:k8s/k8s.io%2Fkubernetes@1.27.4",
								},
								DependsOn: []string{
									"k8s.io/apiserver@1.27.4",
									"k8s.io/controller-manager@1.27.4",
									"k8s.io/kube-proxy@1.27.4",
									"k8s.io/kube-scheduler@1.27.4",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path with infinity loop",
			inputFile: "testdata/happy/infinite-loop-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:08d22c0ceb150ddeb2237c5fa3129c0183f3cc6f5eeb2e7aa4016da3ad02140a",
					DiffIDs: []string{
						"sha256:b93c1bd012ab8fda60f5b4f5906bf244586e0e3292d84571d3abb56472248466",
					},
					RepoTags: []string{
						"ubuntu:latest",
					},
					RepoDigests: []string{
						"ubuntu@sha256:67211c14fa74f070d27cc59d69a7fa9aeff8e28ea118ef3babc295a0428a6d21",
					},
					OS: &ftypes.OS{
						Family: "ubuntu",
						Name:   "22.04",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "libc6@2.35-0ubuntu3.1",
								Name:       "libc6",
								Version:    "2.35-0ubuntu3.1",
								SrcName:    "glibc",
								SrcVersion: "2.35",
								SrcRelease: "0ubuntu3.1",
								Licenses: []string{
									"LGPL-2.1",
									"GPL-2.0",
									"GFDL-1.3",
								},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "ubuntu",
										Name:      "libc6",
										Version:   "2.35-0ubuntu3.1",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "ubuntu-22.04",
											},
										},
									},
									BOMRef: "pkg:deb/ubuntu/libc6@2.35-0ubuntu3.1?distro=ubuntu-22.04",
								},
								DependsOn: []string{
									"libcrypt1@1:4.4.27-1",
								},
								Layer: ftypes.Layer{
									Digest: "sha256:74ac377868f863e123f24c409f79709f7563fa464557c36a09cf6f85c8b92b7f",
									DiffID: "sha256:b93c1bd012ab8fda60f5b4f5906bf244586e0e3292d84571d3abb56472248466",
								},
							},
							{
								ID:         "libcrypt1@1:4.4.27-1",
								Name:       "libcrypt1",
								Version:    "4.4.27-1",
								Epoch:      1,
								SrcName:    "libxcrypt",
								SrcVersion: "4.4.27",
								SrcRelease: "1",
								SrcEpoch:   1,
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "ubuntu",
										Name:      "libcrypt1",
										Version:   "4.4.27-1",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "ubuntu-22.04",
											},
											{
												Key:   "epoch",
												Value: "1",
											},
										},
									},
									BOMRef: "pkg:deb/ubuntu/libcrypt1@4.4.27-1?epoch=1&distro=ubuntu-22.04",
								},
								DependsOn: []string{
									"libc6@2.35-0ubuntu3.1",
								},
								Layer: ftypes.Layer{
									Digest: "sha256:74ac377868f863e123f24c409f79709f7563fa464557c36a09cf6f85c8b92b7f",
									DiffID: "sha256:b93c1bd012ab8fda60f5b4f5906bf244586e0e3292d84571d3abb56472248466",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for third party sbom",
			inputFile: "testdata/happy/third-party-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
				Packages: []ftypes.PackageInfo{
					{
						Packages: ftypes.Packages{
							{
								ID:         "musl@1.2.3-r0",
								Name:       "musl",
								Version:    "1.2.3-r0",
								SrcName:    "musl",
								SrcVersion: "1.2.3-r0",
								Licenses:   []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeApk,
										Namespace: "alpine",
										Name:      "musl",
										Version:   "1.2.3-r0",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "distro",
												Value: "3.16.0",
											},
										},
									},
									BOMRef: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.0",
								},
							},
						},
					},
				},
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Libraries: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
								Licenses: []string{"MIT"},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for third party sbom, no operation-system component",
			inputFile: "testdata/happy/third-party-bom-no-os.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Libraries: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for unrelated bom",
			inputFile: "testdata/happy/unrelated-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Libraries: ftypes.Packages{
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for independent library bom",
			inputFile: "testdata/happy/independent-library-bom.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     "composer",
						FilePath: "",
						Libraries: ftypes.Packages{
							{
								ID:      "pear/core@1.13.1",
								Name:    "pear/core",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "core",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/core@1.13.1",
								},
								DependsOn: []string{
									"pear/log@1.13.1",
									"pear/pear_exception@v1.0.0",
								},
							},
							{
								ID:      "pear/log@1.13.1",
								Name:    "pear/log",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "log",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/log@1.13.1",
								},
							},
							{
								ID:      "pear/pear_exception@v1.0.0",
								Name:    "pear/pear_exception",
								Version: "v1.0.0",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "pear_exception",
										Version:   "v1.0.0",
									},
									BOMRef: "pkg:composer/pear/pear_exception@v1.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for jar where name is GroupID and ArtifactID",
			inputFile: "testdata/happy/group-in-name.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: "jar",
						Libraries: ftypes.Packages{
							{
								ID:      "org.springframework:spring-web:5.3.22",
								Name:    "org.springframework:spring-web",
								Version: "5.3.22",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "org.springframework",
										Name:      "spring-web",
										Version:   "5.3.22",
									},
									BOMRef: "pkg:maven/org.springframework/spring-web@5.3.22?file_path=spring-web-5.3.22.jar",
								},
								FilePath: "spring-web-5.3.22.jar",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path only os component",
			inputFile: "testdata/happy/os-only-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:49193a2310dbad4c02382da87ac624a80a92387a4f7536235f9ba590e5bcd7b5",
					DiffIDs: []string{
						"sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
						"sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
					},
					RepoTags: []string{
						"maven-test-project:latest",
					},
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.16.0",
					},
				},
			},
		},
		{
			name:      "happy path empty component",
			inputFile: "testdata/happy/empty-bom.json",
			want: types.SBOM{
				Metadata: types.Metadata{
					ImageID: "sha256:49193a2310dbad4c02382da87ac624a80a92387a4f7536235f9ba590e5bcd7b5",
					DiffIDs: []string{
						"sha256:3c79e832b1b4891a1cb4a326ef8524e0bd14a2537150ac0e203a5677176c1ca1",
						"sha256:dd565ff850e7003356e2b252758f9bdc1ff2803f61e995e24c7844f6297f8fc3",
					},
					RepoTags: []string{
						"maven-test-project:latest",
					},
				},
			},
		},
		{
			name:      "happy path empty metadata component",
			inputFile: "testdata/happy/empty-metadata-component-bom.json",
			want:      types.SBOM{},
		},
		{
			name:      "invalid purl",
			inputFile: "testdata/happy/invalid-purl.json",
			want: types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.Composer,
						Libraries: ftypes.Packages{
							{
								ID:      "pear/core@1.13.1",
								Name:    "pear/core",
								Version: "1.13.1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeComposer,
										Namespace: "pear",
										Name:      "core",
										Version:   "1.13.1",
									},
									BOMRef: "pkg:composer/pear/core@1.13.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "invalid serial",
			inputFile: "testdata/sad/invalid-serial.json",
			wantErr:   "CycloneDX decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			var cdx cyclonedx.BOM
			err = json.NewDecoder(f).Decode(&cdx)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			var got types.SBOM
			err = sbomio.NewDecoder(cdx.BOM).Decode(&got)
			require.NoError(t, err)

			got.BOM = nil
			assert.Equal(t, tt.want, got)
		})
	}
}
