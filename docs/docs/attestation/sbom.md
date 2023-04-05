# SBOM attestation

[Cosign](https://github.com/sigstore/cosign) supports generating and verifying [in-toto attestations](https://github.com/in-toto/attestation). This tool enables you to sign and verify SBOM attestation.
And, Trivy can take an SBOM attestation as input and scan for vulnerabilities

!!! note
    In the following examples, the `cosign` command will write an attestation to a target OCI registry, so you must have permission to write.
    If you want to avoid writing an OCI registry and only want to see an attestation, add the `--no-upload` option to the `cosign` command.

## Sign with a local key pair

Cosign can generate key pairs and use them for signing and verification. After you run the following command, you will get a public and private key pair. Read more about [how to generate key pairs](https://docs.sigstore.dev/cosign/key-generation).

```bash
$ cosign generate-key-pair
```

In the following example, Trivy generates an SBOM in the CycloneDX format, and then Cosign attaches an attestation of the SBOM to a container image with a local key pair.

```bash
# The cyclonedx type is supported in Cosign v1.10.0 or later.
$ trivy image --format cyclonedx -o sbom.cdx.json <IMAGE>
$ cosign attest --key /path/to/cosign.key --type cyclonedx --predicate sbom.cdx.json <IMAGE>
```

Then, you can verify attestations on the image.

```bash
$ cosign verify-attestation --key /path/to/cosign.pub --type cyclonedx <IMAGE>
```

You can also create attestations of other formatted SBOM.

```bash
# spdx
$ trivy image --format spdx -o sbom.spdx <IMAGE>
$ cosign attest --key /path/to/cosign.key --type spdx --predicate sbom.spdx <IMAGE>

# spdx-json
$ trivy image --format spdx-json -o sbom.spdx.json <IMAGE>
$ cosign attest --key /path/to/cosign.key --type spdx --predicate sbom.spdx.json <IMAGE>
```

## Keyless signing

You can use Cosign to sign without keys by authenticating with an OpenID Connect protocol supported by sigstore (Google, GitHub, or Microsoft).

```bash
# The cyclonedx type is supported in Cosign v1.10.0 or later.
$ trivy image --format cyclonedx -o sbom.cdx.json <IMAGE>
# The following command uploads SBOM attestation to the public Rekor instance.
$ COSIGN_EXPERIMENTAL=1 cosign attest --type cyclonedx --predicate sbom.cdx.json <IMAGE>
```

You can verify attestations.
```bash
$ COSIGN_EXPERIMENTAL=1 cosign verify-attestation --type cyclonedx <IMAGE>
```

## Scanning

Trivy can take an SBOM attestation as input and scan for vulnerabilities. Currently, Trivy supports SPDX & CycloneDX (`cyclonedx`, `spdx`, `spdx-json`) type attestations.

In the following example, Cosign can get an `spdxjson` type attestation and trivy scan it. ([See here](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md) for all of the cosign attestation types supported).
You must create spdx-json type attestation before trying the example.
To learn more about how to create an attestation and attach it to an image, see the [Sign with a local key pair](#sign-with-a-local-key-pair) section.

```bash
# assuming it's attested as... 
# trivy image --format spdx-json -o sbom-in.spdx.json ${IMAGE}
# cosign attest --key vendor.key --type spdxjson --predicate sbom-in.spdx.json ${IMAGE}

# verify and extract spdx payload (predicate) from base64 encoded statement in the intoto envelope
$ cosign verify-attestation --key vendor.pub --type spdxjson ${IMAGE} | jq -r '.payload' | base64 -d | jq -r '.predicate' > sbom-out.spdx.json
$ trivy sbom ./sbom-out.spdx.json

sbom-out.spdx.json (alpine 3.7.3)
=========================
Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 2)

┌────────────┬────────────────┬──────────┬───────────────────┬───────────────┬──────────────────────────────────────────────────────────┐
│  Library   │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                          Title                           │
├────────────┼────────────────┼──────────┼───────────────────┼───────────────┼──────────────────────────────────────────────────────────┤
│ musl       │ CVE-2019-14697 │ CRITICAL │ 1.1.18-r3         │ 1.1.18-r4     │ musl libc through 1.1.23 has an x87 floating-point stack │
│            │                │          │                   │               │ adjustment im ......                                     │
│            │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2019-14697               │
├────────────┤                │          │                   │               │                                                          │
│ musl-utils │                │          │                   │               │                                                          │
│            │                │          │                   │               │                                                          │
│            │                │          │                   │               │                                                          │
└────────────┴────────────────┴──────────┴───────────────────┴───────────────┴──────────────────────────────────────────────────────────┘
```
