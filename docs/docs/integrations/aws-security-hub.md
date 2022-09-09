# AWS Security Hub

## Upload findings to Security Hub

In the following example using the template [asff-cli.tpl](/contrib/asff-cli.tpl), a list of [ASFFs](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) are generated.

```
$ AWS_REGION=us-west-1 AWS_ACCOUNT_ID=123456789012 trivy image --format template --template "@contrib/asff-cli.tpl" -o report.asff golang:1.12-alpine
```

ASFF template needs AWS_REGION and AWS_ACCOUNT_ID from environment variables.

The Product [ARN](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) field follows the pattern below to match what AWS requires for the [product resource type](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecurityhub.html).

```
"ProductArn": "arn:aws:securityhub:{{ env "AWS_REGION" }}:{{ env "AWS_ACCOUNT_ID" }}:product/aquasecurity/trivy",
```

Then, you can upload it with AWS CLI.

```
$ aws securityhub batch-import-findings --findings file://report.asff
```

Security Findings uploaded through the [API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html) are expected to be a JSON object with `Findings` as the key. For this output set `--template` to a value of `"@contrib/asff.tpl"`.

## Customize
You can customize [asff.tpl](https://github.com/aquasecurity/trivy/blob/main/contrib/asff.tpl)

```
$ export AWS_REGION=us-west-1
$ export AWS_ACCOUNT_ID=123456789012
$ trivy image --format template --template "@your-asff.tpl" -o report.asff golang:1.12-alpine
```

## Reference
https://aws.amazon.com/blogs/security/how-to-build-ci-cd-pipeline-container-vulnerability-scanning-trivy-and-aws-security-hub/
