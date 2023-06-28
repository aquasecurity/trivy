# Signature Verification

All binaries and container images are signed by [Cosign](https://github.com/sigstore/cosign).

You need the following tools:

- [Cosign](https://docs.sigstore.dev/cosign/installation/)
- [jq](https://jqlang.github.io/jq/download/)

## Verifying signed container images
1. Use the following command for keyless [verification](https://docs.sigstore.dev/cosign/verify/):
```shell
cosign verify aquasec/trivy:<version> \
--certificate-identity-regexp 'https://github\.com/aquasecurity/trivy/\.github/workflows/.+' \
--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
| jq .
```
2. You should get the following output
```shell
Verification for index.docker.io/aquasec/trivy:latest --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates

  ....
```

## Verifying signed binaries

1. Download the required binary and associated signature and certificate files
2. Use the following command for keyless verification:
```shell
cosign verify-blob <path to binray> \
--certificate <path to cert> \
--signature $(cat <path to sig>) \
--certificate-identity-regexp 'https://github\.com/aquasecurity/trivy/\.github/workflows/.+' \
--certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```
3. You should get the following output
```
Verified OK
```