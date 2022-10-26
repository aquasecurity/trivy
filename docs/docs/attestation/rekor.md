# Scan SBOM attestation in Rekor

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

## Container images
Trivy can retrieve SBOM attestation of the specified container image in the [Rekor][rekor] instance and scan it for vulnerabilities.

### Prerequisites
1. SBOM attestation stored in Rekor
    - See [the "Keyless signing" section][sbom-attest] if you want to upload your SBOM attestation to Rekor.
 

### Scanning
You need to pass `--sbom-sources rekor` so that Trivy will look for SBOM attestation in Rekor.

!!! note
    `--sbom-sources` can be used only with `trivy image` at the moment.

```bash
$ trivy image --sbom-sources rekor otms61/alpine:3.7.3                                                                            [~/src/github.com/aquasecurity/trivy]
2022-09-16T17:37:13.258+0900	INFO	Vulnerability scanning is enabled
2022-09-16T17:37:13.258+0900	INFO	Secret scanning is enabled
2022-09-16T17:37:13.258+0900	INFO	If your scanning is slow, please try '--security-checks vuln' to disable secret scanning
2022-09-16T17:37:13.258+0900	INFO	Please see also https://aquasecurity.github.io/trivy/dev/docs/secret/scanning/#recommendation for faster secret detection
2022-09-16T17:37:14.827+0900	INFO	Detected SBOM format: cyclonedx-json
2022-09-16T17:37:14.901+0900	INFO	Found SBOM (cyclonedx) attestation in Rekor
2022-09-16T17:37:14.903+0900	INFO	Detected OS: alpine
2022-09-16T17:37:14.903+0900	INFO	Detecting Alpine vulnerabilities...
2022-09-16T17:37:14.907+0900	INFO	Number of language-specific files: 0
2022-09-16T17:37:14.908+0900	WARN	This OS version is no longer supported by the distribution: alpine 3.7.3
2022-09-16T17:37:14.908+0900	WARN	The vulnerability detection may be insufficient because security updates are not provided

otms61/alpine:3.7.3 (alpine 3.7.3)
==================================
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

If you have your own Rekor instance, you can specify the URL via `--rekor-url`.

```bash
$ trivy image --sbom-sources rekor --rekor-url https://my-rekor.dev otms61/alpine:3.7.3
```

## Non-packaged binaries
Trivy can retrieve SBOM attestation of non-packaged binaries in the [Rekor][rekor] instance and scan it for vulnerabilities.

### Prerequisites
1. SBOM attestation stored in Rekor
    - See [the "Keyless signing" section][sbom-attest] if you want to upload your SBOM attestation to Rekor.

Cosign currently does not support keyless signing for blob attestation, so use our plugin at the moment.
This example uses a cat clone [bat][bat] written in Rust.
You need to generate SBOM from lock files like `Cargo.lock` at first.

```bash
$ git clone -b v0.20.0 https://github.com/sharkdp/bat
$ trivy fs --format cyclonedx --output bat.cdx ./bat/Cargo.lock
```

Then [our attestation plugin][plugin-attest] allows you to store the SBOM attestation linking to a `bat` binary in the Rekor instance.

```bash
$ wget https://github.com/sharkdp/bat/releases/download/v0.20.0/bat-v0.20.0-x86_64-apple-darwin.tar.gz
$ tar xvf bat-v0.20.0-x86_64-apple-darwin.tar.gz
$ trivy plugin install github.com/aquasecurity/trivy-plugin-attest
$ trivy attest --predicate ./bat.cdx --type cyclonedx ./bat-v0.20.0-x86_64-apple-darwin/bat
```

### Scan a non-packaged binary
Trivy calculates the digest of the `bat` binary and searches for the SBOM attestation by the digest in Rekor.
If it is found, Trivy uses that for vulnerability scanning.

```bash
$ trivy fs --sbom-sources rekor ./bat-v0.20.0-x86_64-apple-darwin/bat
2022-10-25T13:27:25.950+0300    INFO    Found SBOM attestation in Rekor: bat
2022-10-25T13:27:25.993+0300    INFO    Number of language-specific files: 1
2022-10-25T13:27:25.993+0300    INFO    Detecting cargo vulnerabilities...

bat (cargo)
===========
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

┌───────────┬───────────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────────────────────────────┐
│  Library  │   Vulnerability   │ Severity │ Installed Version │ Fixed Version │                           Title                            │
├───────────┼───────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ regex     │ CVE-2022-24713    │ HIGH     │ 1.5.4             │ 1.5.5         │ Mozilla: Denial of Service via complex regular expressions │
│           │                   │          │                   │               │ https://avd.aquasec.com/nvd/cve-2022-24713                 │
└───────────┴───────────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────────────────────────────┘
```

Also, it is applied to non-packaged binaries even in container images.

```bash
$ trivy image --sbom-sources rekor --security-checks vuln alpine-with-bat
2022-10-25T13:40:14.920+0300    INFO    Vulnerability scanning is enabled
2022-10-25T13:40:18.047+0300    INFO    Found SBOM attestation in Rekor: bat
2022-10-25T13:40:18.186+0300    INFO    Detected OS: alpine
2022-10-25T13:40:18.186+0300    INFO    Detecting Alpine vulnerabilities...
2022-10-25T13:40:18.199+0300    INFO    Number of language-specific files: 1
2022-10-25T13:40:18.199+0300    INFO    Detecting cargo vulnerabilities...

alpine-with-bat (alpine 3.15.6)
===============================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


bat (cargo)
===========
Total: 4 (UNKNOWN: 3, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

┌───────────┬───────────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────────────────────────────┐
│  Library  │   Vulnerability   │ Severity │ Installed Version │ Fixed Version │                           Title                            │
├───────────┼───────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ regex     │ CVE-2022-24713    │ HIGH     │ 1.5.4             │ 1.5.5         │ Mozilla: Denial of Service via complex regular expressions │
│           │                   │          │                   │               │ https://avd.aquasec.com/nvd/cve-2022-24713                 │
└───────────┴───────────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────────────────────────────┘
```


!!! note
    The `--sbom-sources rekor` flag slows down the scanning as it queries Rekor on the Internet for all non-packaged binaries.

[rekor]: https://github.com/sigstore/rekor
[sbom-attest]: sbom.md#keyless-signing

[plugin-attest]: https://github.com/aquasecurity/trivy-plugin-attest

[bat]: https://github.com/sharkdp/bat