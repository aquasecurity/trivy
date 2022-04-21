# Secret Scanning

Trivy scans any container image, filesystem and git repository to detect exposed secrets like passwords, api keys, and tokens.
Secret scanning is enabled by default.

Trivy will scan every plaintext file, according to builtin rules or configuration. There are plenty of builtin rules:

- AWS access key
- GCP service account
- GitHub personal access token
- GitLab personal access token
- Slack access token
- etc.

You can see a full list of builtin rules [here][builtin].


## Quick start
This section shows how to scan secrets in container image and filesystem. Other subcommands should be the same.

### Container image
Specify an image name.

``` shell
$ trivy image myimage:1.0.0
2022-04-21T18:56:44.099+0300    INFO    Detected OS: alpine
2022-04-21T18:56:44.099+0300    INFO    Detecting Alpine vulnerabilities...
2022-04-21T18:56:44.101+0300    INFO    Number of language-specific files: 0

myimage:1.0.0 (alpine 3.15.0)
=============================
Total: 6 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 2)

+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
|   LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| busybox      | CVE-2022-28391   | CRITICAL | 1.34.1-r3         | 1.34.1-r5     | CVE-2022-28391 affecting              |
|              |                  |          |                   |               | package busybox 1.35.0                |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2022-28391 |
+--------------+------------------|          |-------------------+---------------+---------------------------------------+
| ssl_client   | CVE-2022-28391   |          | 1.34.1-r3         | 1.34.1-r5     | CVE-2022-28391 affecting              |
|              |                  |          |                   |               | package busybox 1.35.0                |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2022-28391 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+

app/secret.sh (secrets)
=======================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1)

+----------+-------------------+----------+---------+--------------------------------+
| CATEGORY |    DESCRIPTION    | SEVERITY | LINE NO |             MATCH              |
+----------+-------------------+----------+---------+--------------------------------+
|   AWS    | AWS Access Key ID | CRITICAL |   10    | export AWS_ACCESS_KEY_ID=***** |
+----------+-------------------+----------+---------+--------------------------------+
```


!!! tip
    Trivy tries to detect a base image and skip those layers for secret scanning.
    A base image usually contains a lot of files and makes secret scanning much slower.
    If a secret is not detected properly, you can see base layers with the `--debug` flag.

### Filesystem

``` shell
$ trivy fs /path/to/your_project
...(snip)...

certs/key.pem (secrets)
========================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+----------------------+------------------------+----------+---------+---------------------------------+
|       CATEGORY       |      DESCRIPTION       | SEVERITY | LINE NO |              MATCH              |
+----------------------+------------------------+----------+---------+---------------------------------+
| AsymmetricPrivateKey | Asymmetric Private Key |   HIGH   |    1    | -----BEGIN RSA PRIVATE KEY----- |
+----------------------+------------------------+----------+---------+---------------------------------+
```


!!! tip
    Your project may have some secrets for testing. You can skip them with `--skip-dirs` or `--skip-files`.
    We would recommend specifying these options so that the secret scanning can be faster if those files don't need to be scanned.
    Also, you can specify paths to be allowed in a configuration file. See the detail [here][configuration].   

## Configuration
Trivy has a set of builtin rules for secret scanning, which can be extended or modified by a configuration file.

If you don't need secret scanning, you can disable it via the `--security-checks` flag.

```shell
$ trivy image --security-checks vuln alpine:3.15
```

## Credit
This feature is inspired by [gitleaks][gitleaks]. 

[builtin]: https://github.com/aquasecurity/fanal/blob/main/secret/builtin.go
[configuration]: ./configuration.md
[gitleaks]: https://github.com/zricethezav/gitleaks