Trivy uses Google Cloud SDK. You don't need to install `gcloud` command.

If you want to use target project's repository, you can settle via `GOOGLE_APPLICATION_CREDENTIAL`.
```bash
# must set TRIVY_USERNAME empty char
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credential.json
```
