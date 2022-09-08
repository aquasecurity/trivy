# AWS Security Hub

## Upload findings to Security Hub

In the following example using the template `asff.tpl`, [ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) file can be generated.

```
$ AWS_REGION=us-west-1 AWS_ACCOUNT_ID=123456789012 trivy image --format template --template "@contrib/asff.tpl" -o report.asff golang:1.12-alpine
```

ASFF template needs AWS_REGION and AWS_ACCOUNT_ID from environment variables.

The Product [ARN](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) field follows the pattern below to match what AWS requires for the [product resource type](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html#securityhub-custom-providers-bfi-reqs:~:text=Use%20this%20product%20ARN%20as%20the%20value%20for%20the%20ProductArn%20attribute%20when%20invoking%20the%20BatchImportFindings%20API%20operation.).

```
"ProductArn": "arn:aws:securityhub:{{ env "AWS_REGION" }}:{{ env "AWS_ACCOUNT_ID" }}:product/{{ env "AWS_ACCOUNT_ID" }}/default",
```

Then, you can upload it with AWS CLI.

```
$ aws securityhub batch-import-findings --findings file://report.asff
```

## Customize
You can customize [asff.tpl](https://github.com/aquasecurity/trivy/blob/main/contrib/asff.tpl)

```
$ export AWS_REGION=us-west-1
$ export AWS_ACCOUNT_ID=123456789012
$ trivy image --format template --template "@your-asff.tpl" -o report.asff golang:1.12-alpine
```

## Reference
https://aws.amazon.com/blogs/security/how-to-build-ci-cd-pipeline-container-vulnerability-scanning-trivy-and-aws-security-hub/
