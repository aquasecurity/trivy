# Cryptographic Asset Scanning

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy inventories the cryptographic material it finds in a container image and reports it as a CBOM (Cryptography Bill of Materials). The CBOM lists the certificates and keys themselves and the algorithms they use. The result is part of the CycloneDX report, next to the software components. In JSON output Trivy also reports [weak assets](#findings) found by built-in checks.

The scanner is off by default. Enable it with `--scanners crypto` together with `--format cyclonedx` or `--format json`.

```shell
$ trivy image --scanners crypto --format cyclonedx --output result.cdx.json myimage:1.0.0
$ trivy image --scanners crypto --format json --output result.json myimage:1.0.0
```

Trivy rejects `--scanners crypto` with other report formats.

## What is scanned

Files are selected by extension: `.pem`, `.der`, `.crt`, `.cer`, `.key`. The encoding comes from the content, since these extensions carry both PEM and DER.

Keystores are selected by the `.p12`, `.pfx`, `.jks` and `.keystore` extensions and by the exact file name `cacerts` of the Java trust store. A `.jks` file is read when it holds PKCS#12, which keytool writes by default since JDK 9.

| Material | Formats |
| --- | --- |
| X.509 certificates | PEM, DER, PKCS#12 keystores |
| Private keys | PKCS#1, PKCS#8, SEC1, in PEM or DER |
| Public keys | PKIX, in PEM or DER |
| Encrypted private keys | PKCS#8 in PEM or DER, legacy encrypted PEM |

A single file may hold many objects. A certificate chain, a CA bundle of several hundred certificates, or a certificate stored next to its key are all read block by block, and an entry Trivy cannot read is skipped without discarding the rest of the file.

## What is reported

The report lists three kinds of assets, which are certificates, keys and algorithms. A certificate adds four assets linked to each other. These are the certificate, the key it carries, the algorithm of that key and the algorithm it was signed with. A key is linked to its algorithm, and a private key also to its public key.

A private key is reported with its size and algorithm, but the report never carries key values. Trivy does not decrypt an encrypted key, so the report records only its format and a digest.

A key that Trivy cannot decode, such as an Ed448, X25519, X448 or RSA-PSS key, is described from the algorithm OID in its encoding. Its size is reported only when the OID fixes it, as for Ed448, X25519 and X448, so an RSA-PSS key has no size. An algorithm that Trivy does not recognize is named by its OID, such as `1.3.101.110` for X25519.

An asset is identified by its content. For a certificate this is the SHA-256 of the DER, for a key the SHA-256 of the `SubjectPublicKeyInfo`, and for an algorithm the OID with its parameters. In CycloneDX output the same asset found in several files and layers is reported once, with a list of the places it was found, and each place states the file path and the layer. In JSON output `CryptoAssets` has one entry per place.

The parameters of an algorithm are the key size for RSA and the curve for EC. For DSA they are the two bit lengths that name a parameter set in FIPS 186: L, the length of the prime `p`, and N, the length of the prime `q`. So DSA keys of (2048, 224) and (2048, 256) belong to different algorithms, although both are named `DSA-2048` after the CycloneDX naming pattern. Other algorithms are identified by the OID alone.

### Security levels

Trivy estimates two nominal security levels for the algorithms it recognizes. The classical security level is the strength in bits against classical attacks. The NIST quantum security level is the NIST post-quantum security category from 1 to 5, or 0 for an algorithm that meets none of the categories.

The levels are estimates for an algorithm and its parameters, taken from NIST and IETF publications. They are not a guarantee about an implementation, nor a statement that any policy approves the algorithm.

| Algorithm | Classical security level (bits) | NIST quantum security level |
| --- | --- | --- |
| RSA, key size 1024 / 2048 / 3072 / 4096 / 6144 / 8192 bits | 80 / 112 / 128 / 152 / 176 / 200 | 0 |
| EC, curve P-224 / P-256 / P-384 / P-521 | 112 / 128 / 192 / 256 | 0 |
| DSA, (L, N) of (1024, 160) / (2048, 224) / (2048, 256) / (3072, 256) | 80 / 112 / 112 / 128 | 0 |
| Ed25519 / Ed448 | 128 / 224 | 0 |
| ML-DSA-44 / ML-DSA-65 / ML-DSA-87 | - | 2 / 3 / 5 |
| RSA, ECDSA and DSA signature algorithms | - | 0 |

A dash means that the level is left out of the report.

The levels come from these publications:

- RSA with a key size of 2048 bits and above takes the approximate maximum strengths in Appendix D, Table 4 of [NIST SP 800-56B Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/b/r2/final). RSA with a key size of 1024 bits takes the nominal maximum of 80 from Table 2 of [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final), whose row for a 1024-bit modulus states at most 80 bits.
- EC takes the ECC strength ranges in Table 2 of NIST SP 800-57 Part 1 Rev. 5.
- DSA takes the FFC entries in Table 2 of NIST SP 800-57 Part 1 Rev. 5 and the DSA strengths in Section 3 of [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final). The (1024, 160) pair takes the nominal maximum of 80 from the Table 2 row that states at most 80 bits.
- Ed25519 and Ed448 take their strengths from [RFC 8032, Section 8.5](https://datatracker.ietf.org/doc/html/rfc8032#section-8.5).
- ML-DSA takes its categories from [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
- RSA, EC, DSA and EdDSA rest on integer factorization and discrete logarithms, which a sufficiently capable quantum computer breaks. Section 1.2 of FIPS 204 discusses this. They therefore meet none of the NIST categories.

A level is left out when it cannot be estimated:

- An RSA, ECDSA or DSA signature algorithm gets no classical level. The strength of such a signature is limited by the key that signed it, and that key belongs to the issuer, which the certificate does not carry. Ed25519 and Ed448 are different, because each of their OIDs fixes the curve.
- ML-DSA gets no classical level, because FIPS 204 assigns its parameter sets a NIST category but no classical strength in bits.
- An algorithm whose parameters are not in the table, such as RSA with a key size of 2047 bits or a DSA pair that FIPS 186 does not define, gets no classical level, but still gets a NIST quantum security level of 0.
- An algorithm that Trivy does not recognize, such as RSA-PSS or X25519, gets neither level. An encrypted private key has no algorithm in the report at all, because its algorithm stays inside the ciphertext.

### CycloneDX

Every asset becomes a `cryptographic-asset` component with `cryptoProperties`, and the links between assets are stored in `relatedCryptographicAssets`. Each place an asset was found is an entry in `evidence.occurrences`. The path is stored in `location`, and the layer in `additionalContext` as `aquasecurity:trivy:LayerDiffID=<diff ID>`.

The parameters of an algorithm are stored in `algorithmProperties`. The key size goes to `parameterSetIdentifier`, and for DSA it is the pair `<L>-<N>`, such as `2048-256`, which tells apart two components named `DSA-2048`. The curve goes to `ellipticCurve`. The security levels go to `classicalSecurityLevel` and `nistQuantumSecurityLevel`, and a level that is not estimated is left out.

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

## Findings

Trivy runs built-in checks to find weak cryptographic assets and reports the findings in JSON output. Trivy does not determine whether any software uses these assets.

| Rule ID | Title | Asset | Condition | Severity |
| --- | --- | --- | --- | --- |
| `CRYPTO-0001` | SHA-1 certificate signature | certificate | the signature uses SHA-1 | MEDIUM |
| `CRYPTO-0002` | Small RSA key | key | the RSA key is shorter than 2048 bits | HIGH |
| `CRYPTO-0003` | Weak elliptic curve | algorithm | the classical security level of an EC algorithm is below 112 bits | HIGH |
| `CRYPTO-0004` | Expired certificate | certificate | `NotAfter` is before the time of the scan | MEDIUM |

A key of unknown size or a curve without a security level gives no finding. Certificates in system trust stores are checked too, including old roots signed with SHA-1.

A small RSA key in a certificate gets the finding on its key asset. The EC finding points to the algorithm asset, which is reported once per file, so several keys on one curve in a file give one finding.

A certificate signed with RSA-PSS gives no SHA-1 finding, because Trivy does not read the hash from the RSA-PSS parameters.

Every entry of `CryptoAssets` in JSON output has an `AssetID`, and a finding refers to its asset by this ID. The ID depends on the asset identity, the file path, the layer and the format. Two scans of one image with the same Trivy version give the same IDs. `Evidence` holds the values the check was evaluated on.

```json
{
  "Target": "myimage:1.0.0",
  "Class": "crypto",
  "CryptoAssets": [
    {
      "AssetID": "8c2f0e5a91d34b76",
      "Kind": "key",
      "KeyType": "public",
      "Name": "RSA-1024 public key",
      "FilePath": "app/certs/legacy.pem",
      ...
    },
    ...
  ],
  "CryptoFindings": [
    {
      "RuleID": "CRYPTO-0002",
      "Title": "Small RSA key",
      "Severity": "HIGH",
      "AssetID": "8c2f0e5a91d34b76",
      "Evidence": {
        "KeySize": 1024
      }
    }
  ]
}
```

| Rule ID | Evidence |
| --- | --- |
| `CRYPTO-0001` | `SignatureAlgorithm`, `SignatureAlgorithmOID` |
| `CRYPTO-0002` | `KeySize` |
| `CRYPTO-0003` | `Curve`, `ClassicalSecurityLevel` |
| `CRYPTO-0004` | `NotAfter` |

Findings are evaluated only for JSON output, so they do not affect the exit code of CycloneDX output. `trivy convert` keeps the findings of a JSON report only when converting to JSON, and keeps the cryptographic assets for any format.

## Filtering the inventory

Trivy inventories everything it finds and classifies nothing. A base image brings its own trust store, so a typical scan reports a few hundred public root certificates alongside your own material.

Two attributes in the report separate them. The path says whether a certificate lies in a system trust store such as `/etc/ssl/certs` or `/usr/share/ca-certificates`, and the layer says whether it came from the base image or from your build. A root CA is a CA certificate whose subject and issuer match.

## Client/server mode

The scanner works the same way in [client/server mode](../references/modes/client-server.md).

## Limitations

The scanner is available for `trivy image` only.

Trivy rejects `--scanners crypto` together with [`--sbom-sources`](../target/container_image.md#discover-sbom-referencing-the-container-image), because a remote SBOM found for the image replaces the analysis of its layers.

A file without one of the extensions above is not read, so a key in a file named `tls-key` or inside a config file is missed. You can point the scanner at such a file with [`--file-patterns`](../configuration/skipping.md#customizing-file-handling), as long as it holds PEM or DER material or a PKCS#12 keystore:

```shell
$ trivy image --scanners crypto --format cyclonedx --file-patterns "crypto:etc/app/tls-key" myimage:1.0.0
```

Files larger than 10 MB are skipped, because a file of that size with one of these extensions is almost never cryptographic material.

Some objects are recognized and skipped. Certificate signing requests, CRLs and PKCS#7 bundles are not part of the inventory. OpenSSH keys, JKS and JCEKS keystores and OpenPGP keyrings are not covered yet. A certificate or key that uses an EC key with explicit curve parameters instead of a named curve cannot be parsed and is skipped as well. Private keys of X25519, X448 and Ed448 are skipped, although their public keys are reported.

Trivy does not decrypt PKCS#12 keystores and does not report their private keys, so it reads only the certificates stored without encryption. keytool, OpenSSL and .NET encrypt the certificates unless encryption is turned off explicitly, such as with `-certpbe NONE` in OpenSSL or `-J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE` in keytool. OpenSSL encrypts them even with an empty password. The `cacerts` trust store that ships with JDK 18 and later has no password and is read in full.

The `cacerts` of JDK 17 and earlier is a JKS keystore and is skipped. A PKCS#12 keystore protected by a public-key signature instead of a password-based MAC is not read. Parts of a keystore encoded in BER rather than DER are skipped. Trivy reads at most 10000 bags from one keystore.
