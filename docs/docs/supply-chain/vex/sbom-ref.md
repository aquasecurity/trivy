# External VEX References

!!! warning "EXPERIMENTAL"
This feature might change without preserving backwards compatibility.

## Using externally referenced VEX documents

Trivy can discover and download VEX documents referenced in the `externalReferences` of a scanned CycloneDX SBOM. This
requires the references to be of type `exploitability-statement`.

This is not enabled by default at the moment, but can be activated by explicitly specifying `--vex sbom-ref`.

```
  "externalReferences": [
    {
      "type": "exploitability-statement",
      "url": "https://vex.example.com"
    }
  ]
```

```shell
$ trivy sbom trivy.cdx.json --vex sbom-ref
2025-01-19T13:29:31+01:00       INFO    [vex] Retrieving external VEX document from host vex.example.com type="externalReference"
2025-01-19T13:29:31+01:00       INFO    Some vulnerabilities have been ignored/suppressed. Use the "--show-suppressed" flag to display them.
```

All the referenced VEX files are retrieved via HTTP/HTTPS and used in the same way as if they were explicitly specified
via a [file reference](./file.md).