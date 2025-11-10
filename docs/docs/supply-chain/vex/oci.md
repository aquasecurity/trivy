# Discover VEX Attestation in OCI Registry

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy can discover VEX attestations for container images.
This feature allows you to automatically use VEX during container image scanning.

## How It Works

Trivy can automatically discover and utilize VEX attestations for container images during scanning by using the `--vex oci` flag.
This process enhances vulnerability detection results by incorporating the information from the VEX attestation.

To use this feature, follow these three steps:

1. Create a VEX document
2. Generate and upload a VEX attestation to an OCI registry
3. Use the VEX attestation with Trivy

Steps 1 and 2 are not necessary if you are trying to scan a third-party container image and already have VEX attestation attached.

Let's go through each step in detail.

!!! note
    In the following examples, the `cosign` command will write an attestation to a target OCI registry, so you must have permission to write.
    If you want to avoid writing an OCI registry and only want to see an attestation, add the `--no-upload` option to the cosign command.

### Step 1: Create a VEX Document

Currently, Trivy does not have a built-in feature to create VEX documents, so you need to create them manually.
You can refer to the [OpenVEX section](./file.md#openvex) for guidance on creating VEX files.

For container image vulnerabilities, the product ID should be the OCI type in the [PURL][purl] format.
For example:

```
pkg:oci/trivy?repository_url=ghcr.io/aquasecurity/trivy
```

This product ID applies the VEX statement to all tags of the `ghcr.io/aquasecurity/trivy` container image.
If you want to declare a statement for a specific digest only, you can use:

```
pkg:oci/trivy@sha256:5bd5ab35814f86783561603ebb35d5d5d99006dcdcd5c3f828ea1afb4c12d159?repository_url=ghcr.io/aquasecurity/trivy
```

!!! note
    Using an image tag, like `pkg:oci/trivy?repository_url=ghcr.io/aquasecurity/trivy&tag=0.50.0`, is not supported in the product ID at the moment.

Next, specify vulnerable packages as subcomponents, such as `pkg:apk/alpine/busybox`.
You can also include the package version and other [qualifiers][qualifiers] (e.g., `arch`) to limit statements, like `pkg:apk/alpine/busybox@1.36.1-r29?arch=x86`.

Lastly, include the vulnerability IDs.

Here's an example VEX document:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f",
  "author": "Aqua Security",
  "timestamp": "2024-07-30T19:07:16.853479631-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-42363"
      },
      "products": [
        {
          "@id": "pkg:oci/trivy?repository_url=ghcr.io/aquasecurity/trivy",
          "subcomponents": [
            {"@id": "pkg:apk/alpine/busybox"},
            {"@id": "pkg:apk/alpine/busybox-binsh"}
          ]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
      "impact_statement": "awk is not used"
    }
  ]
}
```

You can also refer to [Trivy's example](https://github.com/aquasecurity/trivy/blob/4e54a7e84c33c1be80c52c6db78c634bc3911715/.vex/oci.openvex.json) for more inspiration.

### Step 2: Generate and Upload a VEX Attestation to an OCI Registry

You can use the [Cosign command](https://docs.sigstore.dev/cosign/verifying/attestation/) to generate and upload the VEX attestation.
Cosign offers methods both with and without keys.
For detailed instructions, please refer to the Cosign documentation.

To generate and attach a VEX attestation to your image, use the following command:

```
$ cosign attest --predicate oci.openvex.json --type openvex <IMAGE>
```

Note that this command attaches the attestation only to the specified image tag.
If needed, repeat the process for other tags and digests.

### Step 3: Use VEX Attestation with Trivy

Once you've attached the VEX attestation to the container image, Trivy can automatically discover and use it during scanning.
Simply add the `--vex oci` flag when scanning a container image:

```
$ trivy image --vex oci <IMAGE>
```

To see which vulnerabilities were filtered by the VEX attestation, use the `--show-suppressed` flag:

```
$ trivy image --vex oci --show-suppressed <IMAGE>
```

The `<IMAGE>` specified in these commands must be the same as the one to which you attached the VEX attestation.

[purl]: https://github.com/package-url/purl-spec
[qualifiers]: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst