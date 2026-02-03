Trivy uses AWS SDK. You don't need to install `aws` CLI tool.
You can use [AWS CLI's ENV Vars][env-var].

[env-var]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html

### AWS private registry permissions

You may need to grant permissions to allow Trivy to pull images from private ECR.

It depends on how you want to provide AWS Role to trivy.

- [IAM Role Service account](https://github.com/aws/amazon-eks-pod-identity-webhook)
- [Kube2iam](https://github.com/jtblin/kube2iam) or [Kiam](https://github.com/uswitch/kiam)

#### IAM Role Service account

Add the AWS role in trivy's service account annotations:

```yaml
trivy:

  serviceAccount:
    annotations: {}
      # eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/IAM_ROLE_NAME
```

#### Kube2iam or Kiam

Add the AWS role to pod's annotations:

```yaml
podAnnotations: {}
  ## kube2iam/kiam annotation
  # iam.amazonaws.com/role: arn:aws:iam::ACCOUNT_ID:role/IAM_ROLE_NAME
```
