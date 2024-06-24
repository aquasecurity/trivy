# Requirements
None, Trivy uses Azure SDK for Go. You don't need to install `az` command.

# Privileges
Service principal must have the `AcrPull` permissions.

## Creation of a service principal
```bash
export SP_DATA=$(az ad sp create-for-rbac --name TrivyTest --role AcrPull --scope "/subscriptions/<subscription_id>/resourceGroups/<resource_group>/providers/Microsoft.ContainerRegistry/registries/<registry_name>")
```

# Usage
```bash
# must set TRIVY_USERNAME empty char
export AZURE_CLIENT_ID=$(echo $SP_DATA | jq -r '.appId')
export AZURE_CLIENT_SECRET=$(echo $SP_DATA | jq -r '.password')
export AZURE_TENANT_ID=$(echo $SP_DATA | jq -r '.tenant')
```

# Testing
You can test credentials in the following manner.

```bash
docker run -it --rm -v /tmp:/tmp \
  -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET -e AZURE_TENANT_ID \
  aquasec/trivy image your_special_project.azurecr.io/your_special_image:your_special_tag
```
