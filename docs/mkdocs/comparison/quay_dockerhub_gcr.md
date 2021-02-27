As `Quay` uses `Clair` internally, it has the same accuracy as `Clair`. `Docker Hub` can scan only official images. `GCR` hardly detects vulnerabilities on Alpine Linux. Also, it is locked to a specific registry.

`Trivy` can be used regardless of the registry, and it is easily integrated with CI/CD services.
