package rekortest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/samber/lo"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/attestation"
)

var (
	indexRes = map[string][]string{
		// Contain a SBOM attestation for a container image
		"sha256:782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02": {
			"392f8ecba72f4326eb624a7403756250b5f2ad58842a99d1653cd6f147f4ce9eda2da350bd908a55",
			"392f8ecba72f4326414eaca77bd19bf5f378725d7fd79309605a81b69cc0101f5cd3119d0a216523",
		},
		// Contain a SBOM attestation for go.mod
		"sha256:23f4e10c43c7654e33a3c9570913c8c9c528292762f1a5c4a97253e9e4e4b238": {
			"24296fb24b8ad77aa715cdfd264ce34c4d544375d7bd7cd029bf5a48ef25217a13fdba562e0889ca",
		},
		// Contain an empty SBOM attestation
		"sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03": {
			"24296fb24b8ad77a8d47be2e40bfe910f0ffc842e86b5685dd85d1c903ef78bb6362125816426fe9",
		},
	}

	imageSBOMAttestation = in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v0.1",
			PredicateType: "https://cyclonedx.org/bom",
			Subject: []in_toto.Subject{
				{
					Name: "index.docker.io/knqyf263/cosign-test",
					Digest: slsa.DigestSet{
						"sha256": "a777c9c66ba177ccfea23f2a216ff6721e78a662cd17019488c417135299cd89",
					},
				},
			},
		},
		Predicate: &attestation.CosignPredicate{
			Data: &cyclonedx.BOM{
				BOMFormat:    cyclonedx.BOMFormat,
				SerialNumber: "urn:uuid:6453fd82-71f4-47c8-ad12-01775619c443",
				SpecVersion:  cyclonedx.SpecVersion1_4,
				Version:      1,
				Metadata: &cyclonedx.Metadata{
					Timestamp: "2022-09-15T13:53:49+00:00",
					Tools: &[]cyclonedx.Tool{
						{
							Vendor:  "aquasecurity",
							Name:    "trivy",
							Version: "dev",
						},
					},
					Component: &cyclonedx.Component{
						BOMRef:     "pkg:oci/alpine@sha256:bc41182d7ef5ffc53a40b044e725193bc10142a1243f395ee852a8d9730fc2ad?repository_url=index.docker.io%2Flibrary%2Falpine\u0026arch=amd64",
						Type:       cyclonedx.ComponentTypeContainer,
						Name:       "alpine:3.16",
						PackageURL: "pkg:oci/alpine@sha256:bc41182d7ef5ffc53a40b044e725193bc10142a1243f395ee852a8d9730fc2ad?repository_url=index.docker.io%2Flibrary%2Falpine\u0026arch=amd64",
						Properties: &[]cyclonedx.Property{
							{Name: "aquasecurity:trivy:SchemaVersion", Value: "2"},
							{Name: "aquasecurity:trivy:ImageID", Value: "sha256:9c6f0724472873bb50a2ae67a9e7adcb57673a183cea8b06eb778dca859181b5"},
							{Name: "aquasecurity:trivy:RepoDigest", Value: "alpine@sha256:bc41182d7ef5ffc53a40b044e725193bc10142a1243f395ee852a8d9730fc2ad"},
							{Name: "aquasecurity:trivy:DiffID", Value: "sha256:994393dc58e7931862558d06e46aa2bb17487044f670f310dffe1d24e4d1eec7"},
							{Name: "aquasecurity:trivy:RepoTag", Value: "alpine:3.16"},
						},
					},
				},
				Components: &[]cyclonedx.Component{
					{
						BOMRef:  "fad4eb97-3d2a-4499-ace7-2c94444148a7",
						Type:    cyclonedx.ComponentTypeOS,
						Name:    "alpine",
						Version: "3.16.2",
						Properties: &[]cyclonedx.Property{
							{Name: "aquasecurity:trivy:Type", Value: "alpine"},
							{Name: "aquasecurity:trivy:Class", Value: "os-pkgs"},
						},
					},
					{
						BOMRef:  "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.2",
						Type:    cyclonedx.ComponentTypeLibrary,
						Name:    "musl",
						Version: "1.2.3-r0",
						Licenses: &cyclonedx.Licenses{
							{Expression: "MIT"},
						},
						PackageURL: "pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.2",
						Properties: &[]cyclonedx.Property{
							{Name: "aquasecurity:trivy:PkgType", Value: "alpine"},
							{Name: "aquasecurity:trivy:SrcName", Value: "musl"},
							{Name: "aquasecurity:trivy:SrcVersion", Value: "1.2.3-r0"},
							{Name: "aquasecurity:trivy:LayerDiffID", Value: "sha256:994393dc58e7931862558d06e46aa2bb17487044f670f310dffe1d24e4d1eec7"},
						},
					},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref: "pkg:oci/alpine@sha256:bc41182d7ef5ffc53a40b044e725193bc10142a1243f395ee852a8d9730fc2ad?repository_url=index.docker.io%2Flibrary%2Falpine&6arch=amd64",
						Dependencies: &[]string{
							"fad4eb97-3d2a-4499-ace7-2c94444148a7",
						},
					},
					{
						Ref: "fad4eb97-3d2a-4499-ace7-2c94444148a7",
						Dependencies: &[]string{
							"pkg:apk/alpine/musl@1.2.3-r0?distro=3.16.2",
						},
					},
				},
			},
		},
	}

	gomodSBOMAttestation = in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v0.1",
			PredicateType: "https://cyclonedx.org/bom",
			Subject: []in_toto.Subject{
				{
					Name: "go.mod",
					Digest: slsa.DigestSet{
						"sha256": "23f4e10c43c7654e33a3c9570913c8c9c528292762f1a5c4a97253e9e4e4b238",
					},
				},
			},
		},
		Predicate: &attestation.CosignPredicate{
			Data: &cyclonedx.BOM{
				BOMFormat:    cyclonedx.BOMFormat,
				SerialNumber: "urn:uuid:8b16c9a3-e957-4c85-b43d-7dd05ea0421c",
				SpecVersion:  cyclonedx.SpecVersion1_4,
				Version:      1,
				Metadata: &cyclonedx.Metadata{
					Timestamp: "2022-10-21T09:50:08+00:00",
					Tools: &[]cyclonedx.Tool{
						{
							Vendor:  "aquasecurity",
							Name:    "trivy",
							Version: "dev",
						},
					},
					Component: &cyclonedx.Component{
						BOMRef: "ef8385d7-a56f-495a-a220-7b0a2e940d39",
						Type:   cyclonedx.ComponentTypeApplication,
						Name:   "go.mod",
						Properties: &[]cyclonedx.Property{
							{Name: "aquasecurity:trivy:SchemaVersion", Value: "2"},
						},
					},
				},
				Components: &[]cyclonedx.Component{
					{
						BOMRef: "bb8b7541-2b08-4692-9363-8f79da5c1a31",
						Type:   cyclonedx.ComponentTypeApplication,
						Name:   "go.mod",
						Properties: &[]cyclonedx.Property{
							{Name: "aquasecurity:trivy:Type", Value: "gomod"},
							{Name: "aquasecurity:trivy:Class", Value: "lang-pkgs"},
						},
					},
					{
						BOMRef:     "pkg:golang/github.com/spf13/cobra@1.5.0",
						Type:       cyclonedx.ComponentTypeLibrary,
						Name:       "github.com/spf13/cobra",
						Version:    "1.5.0",
						PackageURL: "pkg:golang/github.com/spf13/cobra@1.5.0",
						Properties: &[]cyclonedx.Property{
							{Name: "aquasecurity:trivy:PkgType", Value: "gomod"},
						},
					},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref: "ef8385d7-a56f-495a-a220-7b0a2e940d39",
						Dependencies: &[]string{
							"bb8b7541-2b08-4692-9363-8f79da5c1a31",
						},
					},
					{
						Ref: "bb8b7541-2b08-4692-9363-8f79da5c1a31",
						Dependencies: &[]string{
							"pkg:golang/github.com/spf13/cobra@1.5.0",
						},
					},
				},
			},
		},
	}

	emptySBOMAttestation = in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v0.1",
			PredicateType: "https://cyclonedx.org/bom",
		},
		Predicate: &attestation.CosignPredicate{
			Data: &cyclonedx.BOM{
				BOMFormat:   cyclonedx.BOMFormat,
				SpecVersion: cyclonedx.SpecVersion1_4,
				Version:     2,
			},
		},
	}

	entries = map[string]models.LogEntryAnon{
		"392f8ecba72f4326414eaca77bd19bf5f378725d7fd79309605a81b69cc0101f5cd3119d0a216523": {
			Attestation: &models.LogEntryAnonAttestation{
				Data: mustMarshal(imageSBOMAttestation),
			},
			Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaW50b3RvIiwic3BlYyI6eyJjb250ZW50Ijp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI3ODIxNDNlMzlmMWU3YTA0ZTNmNmRhMmQ4OGIxYzA1N2U1NjU3MzYzYzRmOTA2NzlmM2U4YTA3MWI3NjE5ZTAyIn0sInBheWxvYWRIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiZWJiZmRkZGE2Mjc3YWYxOTllOTNjNWJiNWNmNTk5OGE3OTMxMWRlMjM4ZTQ5YmNjOGFjMjQxMDI2OTg3NjFiYiJ9fSwicHVibGljS2V5IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTndSRU5EUVdseFowRjNTVUpCWjBsVllXaHNPRUZSZDFsWlYwNVpiblY2ZGxGdk9FVnJOMWRNVFVSdmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEpkMDlFU1RKTlJFVjRUbnBGTTFkb1kwNU5ha2wzVDBSSk1rMUVSWGxPZWtVelYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZMV21aRVF6bHBhbFZ5Y2xwQldFOWpXRllyUVhGSFJVbFRTbEV6VkhScVNuZEpkRUVLZFRFM1JtbDJhV3BuU2sxaFlVaEdORGNyVDNaMk9WUjFla0ZEUTNscFNVVjVVRFV5WlhJMlptRjVibVpLWVZWcU9FdFBRMEZWYTNkblowWkdUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZIUWxkVUNrTXdkVVUzZFRSUWNVUlZSakZZVjBjMFFsVldWVXBCZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBwUldVUldVakJTUVZGSUwwSkNjM2RIV1VWWVl6SkdlbUl5Um5KaFdFcG9UbXBGZUU1RlFtNWlWMFp3WWtNMWFtSXlNSGRMVVZsTFMzZFpRZ3BDUVVkRWRucEJRa0ZSVVdKaFNGSXdZMGhOTmt4NU9XaFpNazUyWkZjMU1HTjVOVzVpTWpsdVlrZFZkVmt5T1hSTlNVZE1RbWR2Y2tKblJVVkJaRm8xQ2tGblVVTkNTREJGWlhkQ05VRklZMEZEUjBOVE9FTm9VeTh5YUVZd1pFWnlTalJUWTFKWFkxbHlRbGs1ZDNwcVUySmxZVGhKWjFreVlqTkpRVUZCUjBNS01UZHRTbWhuUVVGQ1FVMUJVMFJDUjBGcFJVRm9TMDlCU2tkV1ZsaENiMWN4VERSNGFsazVlV0pXT0daVVVYTjVUU3R2VUVwSWVEazVTMjlMWVVwVlF3cEpVVVJDWkRsbGMxUTBNazFTVG5nM1ZtOUJNMXBhS3pWNGFraE5aV1I2YW1WeFEyWm9aVGN2ZDFweFlUbFVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZDa0ZFUW14QmFrVkJjbkJrZVhsRlJqYzNiMkp5VEVOTVVYcHpZbUl4TTJsc05qZDNkek00WTA1MGFtZE5RbWw2WTJWVWFrUmlZMlZMZVZGU04xUktOSE1LWkVOc2Nsa3hZMUJCYWtFNGFYQjZTVVE0VlUxQ2FHeGtTbVV2WlhKR2NHZHROMnN3TldGaWMybFBOM1Y1ZFZadVMyOVZOazByVFhKNlZWVXJaVGxHZHdwSlJHaENhblZSYTFkUll6MEtMUzB0TFMxRlRrUWdRMFZTVkVsR1NVTkJWRVV0TFMwdExRbz0ifX0=",
			IntegratedTime: lo.ToPtr(int64(1661476639)),
			LogID:          lo.ToPtr("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"),
			LogIndex:       lo.ToPtr(int64(3280165)),
			Verification:   nil, // TODO
		},
		"392f8ecba72f4326eb624a7403756250b5f2ad58842a99d1653cd6f147f4ce9eda2da350bd908a55": {
			Attestation: &models.LogEntryAnonAttestation{
				Data: []byte(`{"apiVersion":"0.0.1","kind":"intoto","spec":{"content":{"hash":{"algorithm":"sha256","value":"782143e39f1e7a04e3f6da2d88b1c057e5657363c4f90679f3e8a071b7619e02"},"payloadHash":{"algorithm":"sha256","value":"ebbfddda6277af199e93c5bb5cf5998a79311de238e49bcc8ac24102698761bb"}},"publicKey":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQWlxZ0F3SUJBZ0lVYWhsOEFRd1lZV05ZbnV6dlFvOEVrN1dMTURvd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ESTJNREV4TnpFM1doY05Nakl3T0RJMk1ERXlOekUzV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVLWmZEQzlpalVyclpBWE9jWFYrQXFHRUlTSlEzVHRqSndJdEEKdTE3Rml2aWpnSk1hYUhGNDcrT3Z2OVR1ekFDQ3lpSUV5UDUyZXI2ZmF5bmZKYVVqOEtPQ0FVa3dnZ0ZGTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVHQldUCkMwdUU3dTRQcURVRjFYV0c0QlVWVUpBd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0pRWURWUjBSQVFIL0JCc3dHWUVYYzJGemIyRnJhWEpoTmpFeE5FQm5iV0ZwYkM1amIyMHdLUVlLS3dZQgpCQUdEdnpBQkFRUWJhSFIwY0hNNkx5OWhZMk52ZFc1MGN5NW5iMjluYkdVdVkyOXRNSUdMQmdvckJnRUVBZFo1CkFnUUNCSDBFZXdCNUFIY0FDR0NTOENoUy8yaEYwZEZySjRTY1JXY1lyQlk5d3pqU2JlYThJZ1kyYjNJQUFBR0MKMTdtSmhnQUFCQU1BU0RCR0FpRUFoS09BSkdWVlhCb1cxTDR4alk5eWJWOGZUUXN5TStvUEpIeDk5S29LYUpVQwpJUURCZDllc1Q0Mk1STng3Vm9BM1paKzV4akhNZWR6amVxQ2ZoZTcvd1pxYTlUQUtCZ2dxaGtqT1BRUURBd05vCkFEQmxBakVBcnBkeXlFRjc3b2JyTENMUXpzYmIxM2lsNjd3dzM4Y050amdNQml6Y2VUakRiY2VLeVFSN1RKNHMKZENsclkxY1BBakE4aXB6SUQ4VU1CaGxkSmUvZXJGcGdtN2swNWFic2lPN3V5dVZuS29VNk0rTXJ6VVUrZTlGdwpJRGhCanVRa1dRYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}}`),
			},
			Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaW50b3RvIiwic3BlYyI6eyJjb250ZW50Ijp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI3ODIxNDNlMzlmMWU3YTA0ZTNmNmRhMmQ4OGIxYzA1N2U1NjU3MzYzYzRmOTA2NzlmM2U4YTA3MWI3NjE5ZTAyIn0sInBheWxvYWRIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiZWJiZmRkZGE2Mjc3YWYxOTllOTNjNWJiNWNmNTk5OGE3OTMxMWRlMjM4ZTQ5YmNjOGFjMjQxMDI2OTg3NjFiYiJ9fSwicHVibGljS2V5IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTndSRU5EUVdseFowRjNTVUpCWjBsVllXaHNPRUZSZDFsWlYwNVpiblY2ZGxGdk9FVnJOMWRNVFVSdmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEpkMDlFU1RKTlJFVjRUbnBGTTFkb1kwNU5ha2wzVDBSSk1rMUVSWGxPZWtVelYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZMV21aRVF6bHBhbFZ5Y2xwQldFOWpXRllyUVhGSFJVbFRTbEV6VkhScVNuZEpkRUVLZFRFM1JtbDJhV3BuU2sxaFlVaEdORGNyVDNaMk9WUjFla0ZEUTNscFNVVjVVRFV5WlhJMlptRjVibVpLWVZWcU9FdFBRMEZWYTNkblowWkdUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZIUWxkVUNrTXdkVVUzZFRSUWNVUlZSakZZVjBjMFFsVldWVXBCZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBwUldVUldVakJTUVZGSUwwSkNjM2RIV1VWWVl6SkdlbUl5Um5KaFdFcG9UbXBGZUU1RlFtNWlWMFp3WWtNMWFtSXlNSGRMVVZsTFMzZFpRZ3BDUVVkRWRucEJRa0ZSVVdKaFNGSXdZMGhOTmt4NU9XaFpNazUyWkZjMU1HTjVOVzVpTWpsdVlrZFZkVmt5T1hSTlNVZE1RbWR2Y2tKblJVVkJaRm8xQ2tGblVVTkNTREJGWlhkQ05VRklZMEZEUjBOVE9FTm9VeTh5YUVZd1pFWnlTalJUWTFKWFkxbHlRbGs1ZDNwcVUySmxZVGhKWjFreVlqTkpRVUZCUjBNS01UZHRTbWhuUVVGQ1FVMUJVMFJDUjBGcFJVRm9TMDlCU2tkV1ZsaENiMWN4VERSNGFsazVlV0pXT0daVVVYTjVUU3R2VUVwSWVEazVTMjlMWVVwVlF3cEpVVVJDWkRsbGMxUTBNazFTVG5nM1ZtOUJNMXBhS3pWNGFraE5aV1I2YW1WeFEyWm9aVGN2ZDFweFlUbFVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZDa0ZFUW14QmFrVkJjbkJrZVhsRlJqYzNiMkp5VEVOTVVYcHpZbUl4TTJsc05qZDNkek00WTA1MGFtZE5RbWw2WTJWVWFrUmlZMlZMZVZGU04xUktOSE1LWkVOc2Nsa3hZMUJCYWtFNGFYQjZTVVE0VlUxQ2FHeGtTbVV2WlhKR2NHZHROMnN3TldGaWMybFBOM1Y1ZFZadVMyOVZOazByVFhKNlZWVXJaVGxHZHdwSlJHaENhblZSYTFkUll6MEtMUzB0TFMxRlRrUWdRMFZTVkVsR1NVTkJWRVV0TFMwdExRbz0ifX0=",
			IntegratedTime: lo.ToPtr(int64(1661476639)),
			LogID:          lo.ToPtr("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"),
			LogIndex:       lo.ToPtr(int64(3280165)),
			Verification:   nil, // TODO
		},
		"24296fb24b8ad77aa715cdfd264ce34c4d544375d7bd7cd029bf5a48ef25217a13fdba562e0889ca": {
			Attestation: &models.LogEntryAnonAttestation{
				Data: mustMarshal(gomodSBOMAttestation),
			},
			Body:           nil, // not used at the moment
			IntegratedTime: lo.ToPtr(int64(1664451604)),
			LogID:          lo.ToPtr("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"),
			LogIndex:       lo.ToPtr(int64(4215471)),
			Verification:   nil, // TODO
		},
		"24296fb24b8ad77a8d47be2e40bfe910f0ffc842e86b5685dd85d1c903ef78bb6362125816426fe9": {
			Attestation: &models.LogEntryAnonAttestation{
				Data: mustMarshal(emptySBOMAttestation),
			},
			Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaW50b3RvIiwic3BlYyI6eyJjb250ZW50Ijp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI3ODIxNDNlMzlmMWU3YTA0ZTNmNmRhMmQ4OGIxYzA1N2U1NjU3MzYzYzRmOTA2NzlmM2U4YTA3MWI3NjE5ZTAyIn0sInBheWxvYWRIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiZWJiZmRkZGE2Mjc3YWYxOTllOTNjNWJiNWNmNTk5OGE3OTMxMWRlMjM4ZTQ5YmNjOGFjMjQxMDI2OTg3NjFiYiJ9fSwicHVibGljS2V5IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTndSRU5EUVdseFowRjNTVUpCWjBsVllXaHNPRUZSZDFsWlYwNVpiblY2ZGxGdk9FVnJOMWRNVFVSdmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEpkMDlFU1RKTlJFVjRUbnBGTTFkb1kwNU5ha2wzVDBSSk1rMUVSWGxPZWtVelYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZMV21aRVF6bHBhbFZ5Y2xwQldFOWpXRllyUVhGSFJVbFRTbEV6VkhScVNuZEpkRUVLZFRFM1JtbDJhV3BuU2sxaFlVaEdORGNyVDNaMk9WUjFla0ZEUTNscFNVVjVVRFV5WlhJMlptRjVibVpLWVZWcU9FdFBRMEZWYTNkblowWkdUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZIUWxkVUNrTXdkVVUzZFRSUWNVUlZSakZZVjBjMFFsVldWVXBCZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBwUldVUldVakJTUVZGSUwwSkNjM2RIV1VWWVl6SkdlbUl5Um5KaFdFcG9UbXBGZUU1RlFtNWlWMFp3WWtNMWFtSXlNSGRMVVZsTFMzZFpRZ3BDUVVkRWRucEJRa0ZSVVdKaFNGSXdZMGhOTmt4NU9XaFpNazUyWkZjMU1HTjVOVzVpTWpsdVlrZFZkVmt5T1hSTlNVZE1RbWR2Y2tKblJVVkJaRm8xQ2tGblVVTkNTREJGWlhkQ05VRklZMEZEUjBOVE9FTm9VeTh5YUVZd1pFWnlTalJUWTFKWFkxbHlRbGs1ZDNwcVUySmxZVGhKWjFreVlqTkpRVUZCUjBNS01UZHRTbWhuUVVGQ1FVMUJVMFJDUjBGcFJVRm9TMDlCU2tkV1ZsaENiMWN4VERSNGFsazVlV0pXT0daVVVYTjVUU3R2VUVwSWVEazVTMjlMWVVwVlF3cEpVVVJDWkRsbGMxUTBNazFTVG5nM1ZtOUJNMXBhS3pWNGFraE5aV1I2YW1WeFEyWm9aVGN2ZDFweFlUbFVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZDa0ZFUW14QmFrVkJjbkJrZVhsRlJqYzNiMkp5VEVOTVVYcHpZbUl4TTJsc05qZDNkek00WTA1MGFtZE5RbWw2WTJWVWFrUmlZMlZMZVZGU04xUktOSE1LWkVOc2Nsa3hZMUJCYWtFNGFYQjZTVVE0VlUxQ2FHeGtTbVV2WlhKR2NHZHROMnN3TldGaWMybFBOM1Y1ZFZadVMyOVZOazByVFhKNlZWVXJaVGxHZHdwSlJHaENhblZSYTFkUll6MEtMUzB0TFMxRlRrUWdRMFZTVkVsR1NVTkJWRVV0TFMwdExRbz0ifX0=",
			IntegratedTime: lo.ToPtr(int64(1661476639)),
			LogID:          lo.ToPtr("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"),
			LogIndex:       lo.ToPtr(int64(3280165)),
			Verification:   nil, // TODO
		},
	}
)

type Server struct {
	ts *httptest.Server
}

func NewServer(t *testing.T) *Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			var params models.SearchIndex
			err := json.NewDecoder(r.Body).Decode(&params)
			require.NoError(t, err)

			if res, ok := indexRes[params.Hash]; ok {
				w.Header().Set("Content-Type", "application/json")
				err = json.NewEncoder(w).Encode(res)
				require.NoError(t, err)
			} else {
				http.Error(w, "something wrong", http.StatusNotFound)
			}
		case "/api/v1/log/entries/retrieve":
			var params models.SearchLogQuery
			err := json.NewDecoder(r.Body).Decode(&params)
			require.NoError(t, err)

			resEntries := models.LogEntry{}
			for _, uuid := range params.EntryUUIDs {
				if e, ok := entries[uuid]; !ok {
					http.Error(w, "no such uuid", http.StatusNotFound)
					return
				} else {
					resEntries[uuid] = e
				}
			}
			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode([]models.LogEntry{resEntries})
			require.NoError(t, err)
		}
		return
	}))

	return &Server{ts: ts}
}

func (s *Server) URL() string {
	return s.ts.URL
}

func (s *Server) Close() {
	s.ts.Close()
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
