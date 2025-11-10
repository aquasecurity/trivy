# Vulnerability Scan Record Attestation

This tutorial details how to

- Scan container images for vulnerabilities
- Generate an attestation, using Cosign, with and without generating a separate key pair

#### Prerequisites

1. [Trivy CLI](../../getting-started/installation.md) installed
2. [Cosign CLI](https://docs.sigstore.dev/cosign/system_config/installation/) installed
3. Ensure that you have access to a container image in a remote container registry that you own/within your account. In this tutorial, we will use DockerHub.

## Scan Container Image for vulnerabilities

Scan your container image for vulnerabilities and save the scan result to a scan.json file:
```
trivy image --ignore-unfixed --format cosign-vuln --output scan.json DockerHubID/imagename:imagetag
```

For example:
```
trivy image --ignore-unfixed --format cosign-vuln --output scan.json anaisurlichs/signed-example:0.1
```

* `--ignore-unfixed`: Ensures only the vulnerabilities, which have a already a fix available, are displayed
* `--output scan.json`: The scan output is saved to a scan.json file instead of being displayed in the terminal.

Note: Replace the container image with the container image that you want to scan.

## Option 1: Signing and Generating an attestation without new key pair

#### Signing

Sign the container image:
```
cosign sign DockerHubID/imagename@imageSHA
```

The `imageSHA` can be obtained through the following docker command:
```
docker image ls --digests
```
The SHA will be displayed next to the image name and tag.

Note that it is better practice to sign the image SHA rather than the tag as the SHA will remain the same for the particular image that we have signed.

For example:
```
cosign sign docker.io/anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd
```

#### Attestation

The following command generates an attestation for the vulnerability scan and uploads it to the container image used:
```
cosign attest --predicate scan.json --type vuln docker.io/DockerHubID/imagename:imageSHA
```

For example:
```
cosign attest --predicate scan.json --type vuln docker.io/anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd
```

Note: Replace the container image with the container image that you would like to scan.

Next, Sigstore will ask you to verify with an account -- Microsoft, GitHub, or Google.

Once done, the user will be provided with a certificate in the terminal where they ran the command. Example certificate:
```
-----BEGIN CERTIFICATE-----
MIIC1TCCAlygAwIBAgIUfSXI7xTWSLq4nuygd8YPuhPZlEswCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjQwMTExMTMzODUzWhcNMjQwMTExMTM0ODUzWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAETcUNnK76mfo9G3j1c7NN6Vcn6yQPDX5rd3QB
unkHs1Uk59CWv3qm6sUyRNYaATs9zdHAZqLck8G4P/Pj7+GzCKOCAXswggF3MA4G
........
-----END CERTIFICATE-----
```


## Option 2: Signing and Generating an attestation with a new Cosign key pair

To generate an attestation for the container image with a separate key pair, we can use Cosign to generate a new key pair:
```
cosign generate-key-pair 
```

This will generate a `cosign.key` and a `cosign.pub` file. The `cosign.key` file is your private key that should be kept confidential as it is used to sign artefacts. However, the `cosign.pub` file contains the information of the corresponding public key. This key can be used by third parties to verify the attestation -- basically that this person who claims to have signed the attestation actually is the one who signed it. 

#### Signing

Sign the container image:
```
cosign sign --key cosign.key docker.io/anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd
```

#### Attestation

To generate the attestation with the specific key pairs, run the following command:
```
cosign attest --key cosign.key --type vuln --predicate scan.json docker.io/anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd 
```

## Verify the attestation

### Option 1 -- No separate key pair

If you have not generated a key pair but received a certificate after the container image was signed, use the following command to verify the attestation:

```
cosign verify-attestation --type vuln --certificate-identity Email-used-to-sign  --certificate-oidc-issuer='the-issuer-used' docker.io/DockerHubID/imagename:imageSHA
```

For example, the command could be like this:
```
cosign verify-attestation --type vuln --certificate-identity urlichsanais@gmail.com  --certificate-oidc-issuer='https://github.com/login/oauth' anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd
```

### Option 2 -- Separate key pair

If you have used a new cosign key pair, the attestation can be verified through the following command:
```
cosign verify-attestation --key cosign.pub --type vuln anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd 
```

<details>
<summary>Output</summary>

The output should look similar to the following:
```
Verification for anaisurlichs/signed-example@sha256:c5911ac313e0be82a740bd726dc290e655800a9588424ba4e0558c705d1287fd --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
{"payloadType":"application/vnd.in-toto+json","payload":
```
</details>

## More information

See [here][vuln-attestation] for more details.

[vuln-attestation]: ../../docs/supply-chain/attestation/vuln.md