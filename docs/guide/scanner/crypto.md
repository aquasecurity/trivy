# Cryptographic Asset Scanning

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy inventories the cryptographic material it finds in a container image and reports it as a CBOM (Cryptography Bill of Materials). The CBOM lists the certificates and keys themselves and the algorithms they use. The result is part of the CycloneDX report, next to the software components.

The scanner is off by default. Enable it with `--scanners crypto` together with `--format cyclonedx`.

```shell
$ trivy image --scanners crypto --format cyclonedx --output result.cdx.json myimage:1.0.0
```

Cryptographic assets have no representation in the other report formats, so Trivy rejects `--scanners crypto` with any of them.

## What is scanned

Files are selected by extension: `.pem`, `.der`, `.crt`, `.cer`, `.key`. The encoding comes from the content, since these extensions carry both PEM and DER.

| Material | Formats |
| --- | --- |
| X.509 certificates | PEM, DER |
| Private keys | PKCS#1, PKCS#8, SEC1, in PEM or DER |
| Public keys | PKIX, in PEM or DER |
| Encrypted private keys | PKCS#8 in PEM or DER, legacy encrypted PEM |

A single file may hold many objects. A certificate chain, a CA bundle of several hundred certificates, or a certificate stored next to its key are all read block by block, and an entry Trivy cannot read is skipped without discarding the rest of the file.

## What is reported

The report lists three kinds of assets, which are certificates, keys and algorithms. A certificate adds four assets linked to each other. These are the certificate, the key it carries, the algorithm of that key and the algorithm it was signed with. A key is linked to its algorithm, and a private key also to its public key.

A private key is reported with its size and algorithm, but the report never carries key values. Trivy does not decrypt an encrypted key, so the report records only its format and a digest.

An asset is identified by its content. For a certificate this is the SHA-256 of the DER, for a key the SHA-256 of the `SubjectPublicKeyInfo`, and for an algorithm the OID with its parameters. The same asset found in several files and layers is therefore reported once, with a list of the places it was found. Each place states the file path and the layer.

### CycloneDX

Every asset becomes a `cryptographic-asset` component with `cryptoProperties`, and the links between assets are stored in `relatedCryptographicAssets`. Each place an asset was found is an entry in `evidence.occurrences`. The path is stored in `location`, and the layer in `additionalContext` as `aquasecurity:trivy:LayerDiffID=<diff ID>`.

```json
{
  "bom-ref": "crypto:certificate:sha256:ab12…",
  "type": "cryptographic-asset",
  "name": "example.com",
  "evidence": {
    "occurrences": [
      {
        "location": "etc/ssl/certs/server.crt",
        "additionalContext": "aquasecurity:trivy:LayerDiffID=sha256:9f3e…"
      }
    ]
  },
  "cryptoProperties": {
    "assetType": "certificate",
    "certificateProperties": {
      "serialNumber": "1a2b",
      "subjectName": "CN=example.com",
      "issuerName": "CN=Example CA",
      "notValidBefore": "2024-01-01T00:00:00+00:00",
      "notValidAfter": "2025-01-01T00:00:00+00:00",
      "certificateFormat": "X.509",
      "fingerprint": { "alg": "SHA-256", "content": "ab12…" },
      "relatedCryptographicAssets": [
        { "type": "algorithm", "ref": "crypto:algorithm:oid:1.2.840.113549.1.1.11" },
        { "type": "publicKey", "ref": "crypto:key:public:spki-sha256:cd34…" }
      ]
    }
  }
}
```

## Filtering the inventory

Trivy inventories everything it finds and classifies nothing. A base image brings its own trust store, so a typical scan reports a few hundred public root certificates alongside your own material.

Two attributes in the report separate them. The path says whether a certificate lies in a system trust store such as `/etc/ssl/certs` or `/usr/share/ca-certificates`, and the layer says whether it came from the base image or from your build. A root CA is a CA certificate whose subject and issuer match.

## Client/server mode

The scanner works the same way in [client/server mode](../references/modes/client-server.md).

## Limitations

The scanner is available for `trivy image` only.

Trivy rejects `--scanners crypto` together with [`--sbom-sources`](../target/container_image.md#discover-sbom-referencing-the-container-image), because a remote SBOM found for the image replaces the analysis of its layers.

A file without one of the extensions above is not read, so a key in a file named `tls-key` or inside a config file is missed. You can point the scanner at such a file with [`--file-patterns`](../configuration/skipping.md#customizing-file-handling), as long as it holds PEM or DER material:

```shell
$ trivy image --scanners crypto --format cyclonedx --file-patterns "crypto:etc/app/tls-key" myimage:1.0.0
```

Files larger than 10 MB are skipped, because a file of that size with one of these extensions is almost never cryptographic material.

Some objects are recognized and skipped. Certificate signing requests, CRLs and PKCS#7 bundles are not part of the inventory. OpenSSH keys, PKCS#12 and JKS keystores and OpenPGP keyrings are not covered yet. A certificate or key that uses an EC key with explicit curve parameters instead of a named curve cannot be parsed and is skipped as well.
