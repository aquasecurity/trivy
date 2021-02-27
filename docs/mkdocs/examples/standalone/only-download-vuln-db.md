You can also ask `Trivy` to simply retrieve the vulnerability database. This is useful to initialize workers in Continuous Integration systems.

```
$ trivy image --download-db-only
```
