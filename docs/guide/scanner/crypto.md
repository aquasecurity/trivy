# Cryptographic Asset Scanning

Trivy inventories the cryptographic material it finds in a container image and reports it as a CBOM (Cryptography Bill of Materials): the certificates and keys themselves, plus the algorithms they use. The result is part of the CycloneDX report, next to the software components.

The scanner is off by default. Enable it with `--scanners crypto` and ask for CycloneDX output.

```shell
$ trivy image --scanners crypto --format cyclonedx --output result.cdx.json myimage:1.0.0
```

Cryptographic assets have no representation in the other report formats, so they are omitted from them and Trivy warns when you ask for one.

## What is scanned

Files are selected by extension: `.pem`, `.der`, `.crt`, `.cer`, `.key`. The encoding comes from the content, since these extensions carry both PEM and DER.

| Material | Formats |
| --- | --- |
| X.509 certificates | PEM, DER |
| Private keys | PKCS#1, PKCS#8, SEC1, in PEM or DER |
| Public keys | PKIX, in PEM or DER |
| Encrypted private keys | PKCS#8 |

A single file may hold many objects. A certificate chain, a CA bundle of several hundred certificates, or a certificate stored next to its key are all read block by block, and an entry Trivy cannot read is skipped without discarding the rest of the file.

Other cryptographic material - OpenSSH keys, PKCS#12 and JKS keystores, OpenPGP keyrings - is not covered yet.

Private key material never leaves the parser: a private key is reduced to its public part, and the report carries no key values. An encrypted key stays closed, so it is recorded as a container with a digest and nothing else.

## What is reported

Every asset becomes a `cryptographic-asset` component with `cryptoProperties`. A certificate contributes up to four of them - the certificate, the key it carries, the algorithm of that key, and the algorithm it was signed with - tied together by `relatedCryptographicAssets`.

An asset is identified by its content: the SHA-256 of the DER for a certificate, the SHA-256 of the `SubjectPublicKeyInfo` for a key, the OID and its parameters for an algorithm. The same certificate found in several files and layers is therefore one component, and each place it was found is an entry in `evidence.occurrences`, with the layer in `additionalContext`.

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto:certificate:sha256:ab12…",
  "name": "CN=example.com",
  "cryptoProperties": {
    "assetType": "certificate",
    "certificateProperties": {
      "subjectName": "CN=example.com",
      "issuerName": "CN=example.com",
      "notValidBefore": "2024-01-01T00:00:00Z",
      "notValidAfter": "2025-01-01T00:00:00Z",
      "certificateFormat": "X.509",
      "fingerprint": { "alg": "SHA-256", "content": "ab12…" },
      "relatedCryptographicAssets": [
        { "type": "algorithm", "ref": "crypto:algorithm:oid:1.2.840.113549.1.1.11" },
        { "type": "publicKey", "ref": "crypto:key:public:spki-sha256:cd34…" }
      ]
    }
  },
  "evidence": {
    "occurrences": [{ "location": "etc/ssl/certs/server.crt" }]
  }
}
```

## Filtering the inventory

Trivy inventories everything it finds and classifies nothing. A base image brings its own trust store, so a typical scan reports a few hundred public root certificates alongside your own material.

Two attributes in the report separate them. The path in `occurrence.location` says whether a certificate lies in a system trust store such as `/etc/ssl/certs` or `/usr/share/ca-certificates`, and the layer in `additionalContext` says whether it came from the base image or from your build. The certificate itself tells you the rest: a root CA is a CA certificate whose subject and issuer match.

## Client/server mode

The scan works the same way against a Trivy server. Files are read on the client, and the assets travel to the server and back with the rest of the analysis.
