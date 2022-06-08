Docker Hub needs `TRIVY_USERNAME` and `TRIVY_PASSWORD`.
You don't need to set ENV vars when download from public repository.

```bash
export TRIVY_USERNAME={DOCKERHUB_USERNAME}
export TRIVY_PASSWORD={DOCKERHUB_PASSWORD}
```
