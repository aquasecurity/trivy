# Cosign Vulnerability Attestation

## Generate Cosign Vulnerability Scan Record

Trivy generates reports in the [Cosign vulnerability scan record format][vuln-attest-spec].

You can use the regular subcommands (like image, fs and rootfs) and specify `cosign-vuln` with the --format option.

```
$ trivy image --format cosign-vuln --output vuln.json alpine:3.10
```

<details>
<summary>Result</summary>

```json
{
  "invocation": {
    "parameters": null,
    "uri": "",
    "event_id": "",
    "builder.id": ""
  },
  "scanner": {
    "uri": "pkg:github/aquasecurity/trivy@v0.30.1-8-gf9cb8a28",
    "version": "v0.30.1-8-gf9cb8a28",
    "db": {
      "uri": "",
      "version": ""
    },
    "result": {
      "SchemaVersion": 2,
      "ArtifactName": "alpine:3.10",
      "ArtifactType": "container_image",
      "Metadata": {
        "OS": {
          "Family": "alpine",
          "Name": "3.10.9",
          "EOSL": true
        },
        "ImageID": "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a",
        "DiffIDs": [
          "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635"
        ],
        "RepoTags": [
          "alpine:3.10"
        ],
        "RepoDigests": [
          "alpine@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98"
        ],
        "ImageConfig": {
          "architecture": "amd64",
          "container": "fdb7e80e3339e8d0599282e606c907aa5881ee4c668a68136119e6dfac6ce3a4",
          "created": "2021-04-14T19:20:05.338397761Z",
          "docker_version": "19.03.12",
          "history": [
            {
              "created": "2021-04-14T19:20:04.987219124Z",
              "created_by": "/bin/sh -c #(nop) ADD file:c5377eaa926bf412dd8d4a08b0a1f2399cfd708743533b0aa03b53d14cb4bb4e in / "
            },
            {
              "created": "2021-04-14T19:20:05.338397761Z",
              "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
              "empty_layer": true
            }
          ],
          "os": "linux",
          "rootfs": {
            "type": "layers",
            "diff_ids": [
              "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635"
            ]
          },
          "config": {
            "Cmd": [
              "/bin/sh"
            ],
            "Env": [
              "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "Image": "sha256:eb2080c455e94c22ae35b3aef9e078c492a00795412e026e4d6b41ef64bc7dd8"
          }
        }
      },
      "Results": [
        {
          "Target": "alpine:3.10 (alpine 3.10.9)",
          "Class": "os-pkgs",
          "Type": "alpine",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2021-36159",
              "PkgName": "apk-tools",
              "InstalledVersion": "2.10.6-r0",
              "FixedVersion": "2.10.7-r0",
              "Layer": {
                "Digest": "sha256:396c31837116ac290458afcb928f68b6cc1c7bdd6963fc72f52f365a2a89c1b5",
                "DiffID": "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635"
              },
              "SeveritySource": "nvd",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-36159",
              "DataSource": {
                "ID": "alpine",
                "Name": "Alpine Secdb",
                "URL": "https://secdb.alpinelinux.org/"
              },
              "Description": "libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strings for the FTP and HTTP protocols. The FTP passive mode implementation allows an out-of-bounds read because strtol is used to parse the relevant numbers into address bytes. It does not check if the line ends prematurely. If it does, the for-loop condition checks for the '\\0' terminator one byte too late.",
              "Severity": "CRITICAL",
              "CweIDs": [
                "CWE-125"
              ],
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
                  "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                  "V2Score": 6.4,
                  "V3Score": 9.1
                }
              },
              "References": [
                "https://github.com/freebsd/freebsd-src/commits/main/lib/libfetch",
                "https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/10749",
                "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cdev.kafka.apache.org%3E",
                "https://lists.apache.org/thread.html/r61db8e7dcb56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cusers.kafka.apache.org%3E",
                "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cdev.kafka.apache.org%3E",
                "https://lists.apache.org/thread.html/rbf4ce74b0d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cusers.kafka.apache.org%3E"
              ],
              "PublishedDate": "2021-08-03T14:15:00Z",
              "LastModifiedDate": "2021-10-18T12:19:00Z"
            }
          ]
        }
      ]
    }
  },
  "metadata": {
    "scanStartedOn": "2022-07-24T17:14:04.864682+09:00",
    "scanFinishedOn": "2022-07-24T17:14:04.864682+09:00"
  }
}
```

</details>

## Create Cosign Vulnerability Attestation

[Cosign](https://github.com/sigstore/cosign) supports generating and verifying [in-toto attestations](https://github.com/in-toto/attestation). This tool enables you to sign and verify Cosign vulnerability attestation.

!!! note
    In the following examples, the `cosign` command will write an attestation to a target OCI registry, so you must have permission to write.
    If you want to avoid writing an OCI registry and only want to see an attestation, add the `--no-upload` option to the `cosign` command.


### Sign with a local key pair

Cosign can generate key pairs and use them for signing and verification. After you run the following command, you will get a public and private key pair. Read more about [how to generate key pairs](https://docs.sigstore.dev/cosign/key-generation).

```bash
$ cosign generate-key-pair
```

In the following example, Trivy generates a cosign vulnerability scan record, and then Cosign attaches an attestation of it to a container image with a local key pair.

```
$ trivy image --format cosign-vuln --output vuln.json <IMAGE>
$ cosign attest --key /path/to/cosign.key --type vuln --predicate vuln.json <IMAGE>
```

Then, you can verify attestations on the image.

```
$ cosign verify-attestation --key /path/to/cosign.pub --type vuln <IMAGE>
```

### Keyless signing

You can use Cosign to sign without keys by authenticating with an OpenID Connect protocol supported by sigstore (Google, GitHub, or Microsoft).

```
$ trivy image --format cosign-vuln -o vuln.json <IMAGE>
$ COSIGN_EXPERIMENTAL=1 cosign attest --type vuln --predicate vuln.json <IMAGE>
```

You can verify attestations.

```
$ COSIGN_EXPERIMENTAL=1 cosign verify-attestation --type vuln <IMAGE>
```

[vuln-attest-spec]: https://github.com/sigstore/cosign/blob/95b74db89941e8ec85e768f639efd4d948db06cd/specs/COSIGN_VULN_ATTESTATION_SPEC.md