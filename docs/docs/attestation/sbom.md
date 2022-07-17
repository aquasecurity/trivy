# SBOM attestation

[Cosign](https://github.com/sigstore/cosign) supports generating and verifying [in-toto attestations](https://github.com/in-toto/attestation). This tool enables you to sign and verify SBOM attestation.

## Sign with a local key pair

In the following example, Trivy generates an SBOM in the spdx format, and then Cosign attaches an attestation of the SBOM to a container image with a local key pair.

```
$ trivy image --format spdx -o predicate <IMAGE>
$ cosign attest --key /path/to/cosign.key --type spdx --predicate predicate <IMAGE>
```

Then, you can verify attestations on the image.

```
$ cosign verify-attestation --key /path/to/cosign.pub <IMAGE>
```

You can also create attestations of other formatted SBOM.

```
# spdx-json
$ trivy image --format spdx-json -o predicate <IMAGE>
$ cosign attest --key /path/to/cosign.key --type spdx --predicate predicate <IMAGE>

# cyclonedx
$ trivy image --format cyclonedx -o predicate <IMAGE>
$ cosign attest --key /path/to/cosign.key --type https://cyclonedx.org/schema --predicate predicate <IMAGE>
```

## Keyless signing

You can use Cosign to sign without keys by authenticating with an OpenID Connect protocol supported by Sigstore (Google, GitHub, or Microsoft).

```
$ trivy image --format spdx -o predicate <IMAGE>
$ COSIGN_EXPERIMENTAL=1 cosign attest --type spdx --predicate predicate <IMAGE>
```

You can verify attestations.
```
$ COSIGN_EXPERIMENTAL=1 cosign verify-attestation <IMAGE>
```
