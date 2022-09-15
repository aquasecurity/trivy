# Scan SBOM attestation in Rekor

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy can retrieve SBOM attestation of the specified container image in the [Rekor][rekor] instance and scan it for vulnerabilities.

## Prerequisites
1. SBOM attestation stored in Rekor
    - See [the "Keyless signing" section][sbom-attest] if you want to upload your SBOM attestation to Rekor.
 

## Scanning
You need to pass `--sbom-sources rekor` so that Trivy will look for SBOM attestation in Rekor.

!!! note
    `--sbom-sources` can be used only with `trivy image` at the moment.

```bash
$ trivy image --sbom-sources rekor otms61/alpine:3.7.3                                                                            [~/src/github.com/aquasecurity/trivy]
2022-09-15T22:16:09.791+0300    INFO    Vulnerability scanning is enabled
2022-09-15T22:16:09.791+0300    INFO    Secret scanning is enabled
2022-09-15T22:16:09.791+0300    INFO    If your scanning is slow, please try '--security-checks vuln' to disable secret scanning
2022-09-15T22:16:09.791+0300    INFO    Please see also https://aquasecurity.github.io/trivy/dev/docs/secret/scanning/#recommendation for faster secret detection
2022-09-15T22:16:15.183+0300    INFO    Detected OS: alpine
2022-09-15T22:16:15.183+0300    INFO    Detecting Alpine vulnerabilities...
2022-09-15T22:16:15.219+0300    INFO    Number of language-specific files: 0
2022-09-15T22:16:15.235+0300    WARN    This OS version is no longer supported by the distribution: alpine 3.7.3
2022-09-15T22:16:15.235+0300    WARN    The vulnerability detection may be insufficient because security updates are not provided

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

[rekor]: https://github.com/sigstore/rekor
[sbom-attest]: sbom.md#keyless-signing