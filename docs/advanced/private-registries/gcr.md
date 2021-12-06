# Requirements
None, Trivy uses Google Cloud SDK. You don't need to install `gcloud` command.

# Privileges
Credential file must have the `roles/storage.objectViewer` permissions.
More information can be found in [Google's documentation](https://cloud.google.com/container-registry/docs/access-control)

## JSON File Format
The JSON file specified should have the following format provided by google's service account mechanisms:

```json
{
  "type": "service_account",
  "project_id": "your_special_project",
  "private_key_id": "XXXXXXXXXXXXXXXXXXXXxx",
  "private_key": "-----BEGIN PRIVATE KEY-----\nNONONONO\n-----END PRIVATE KEY-----\n",
  "client_email": "somedude@your_special_project.iam.gserviceaccount.com",
  "client_id": "1234567890",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/somedude%40your_special_project.iam.gserviceaccount.com"
}
```

# Usage
If you want to use target project's repository, you can set them via `GOOGLE_APPLICATION_CREDENTIALS`.
```bash
# must set TRIVY_USERNAME empty char
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credential.json
```

# Testing
You can test credentials in the following manner (assuming they are in `/tmp` on host machine).

```bash
docker run -it --rm -v /tmp:/tmp\
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/service_account.json\
  aquasec/trivy image gcr.io/your_special_project/your_special_image:your_special_tag
```
