# Vulnerability Scan Record Attestation

This tutorial details 

- Scan your container image for vulnerabilities
- Generate an attestation with Cosign

#### Prerequisites

1. Trivy CLI installed
2. Cosign installed 

#### Scan Container Image for vulnerabilities

Scan your container image for vulnerabilities and save the scan result to a scan.json file:
```
trivy image --ignore-unfixed --format json --output scan.json anaisurlichs/cns-website:0.0.6
```

* --ignore-unfixed: Ensures that only the vulnerabilities are displayed that have a already a fix available
* --output scan.json: The scan output is scaved to a scan.json file instead of being displayed in the terminal.

Note: Replace the container image with the container image that you would like to scan.

#### Attestation of the vulnerability scan with Cosign

The following command generates an attestation for the vulnerability scan and uploads it to our container image:
```
cosign attest --replace --predicate scan.json --type vuln anaisurlichs/cns-website:0.0.6
```

Note: Replace the container image with the container image that you would like to scan.

See [here][vuln-attestation] for more details.

[vuln-attestation]: ../../docs/attestation/vuln.md