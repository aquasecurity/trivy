# Secret Scanning

Trivy scans any container image, filesystem and git repository to detect exposed secrets like passwords, api keys, and tokens.
Secret scanning is enabled by default.

Trivy will scan every plaintext file, according to builtin rules or configuration. Also, Trivy can detect secrets in compiled Python files (`.pyc`).

There are plenty of builtin rules:

- AWS access key
- GCP service account
- GitHub personal access token
- GitLab personal access token
- Slack access token
- etc.

You can see a full list of [built-in rules][builtin] and [built-in allow rules][builtin-allow].

!!! tip
    If your secret is not detected properly, please make sure that your file including the secret is not in [the allowed paths][builtin-allow].
    You can disable allow rules via [disable-allow-rules](#disable-rules).

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
    Also, you can specify paths to be allowed in a configuration file. See the detail [here](#configuration).

## Configuration
This section describes secret-specific configuration.
Other common options are documented [here](../configuration/index.md).

Trivy has a set of builtin rules for secret scanning, which can be extended or modified by a configuration file.
Trivy tries to load `trivy-secret.yaml` in the current directory by default.
If the file doesn't exist, only built-in rules are used.
You can customize the config file path via the `--secret-config` flag.

!!! warning
    Trivy uses [Golang regexp package](https://pkg.go.dev/regexp/syntax#hdr-Syntax). To use `^` and `$` as symbols of begin and end of line use multi-line mode -`(?m)`.

### Custom Rules
Trivy allows defining custom rules.

``` yaml
rules:
  - id: rule1
    category: general
    title: Generic Rule
    severity: HIGH
    path: .*\.sh
    keywords:
      - secret
    regex: (?i)(?P<key>(secret))(=|:).{0,5}['"](?P<secret>[0-9a-zA-Z\-_=]{8,64})['"]
    secret-group-name: secret
    allow-rules:
      - id: skip-text
        description: skip text files
        path: .*\.txt
```

`id` (required)
:   - Unique identifier for this rule.

`category` (required)
:   - String used for metadata and reporting purposes.

`title` (required)
:   - Short human-readable title of the rule.

`severity` (required)
:   - How critical this rule is.
- Allowed values:
- CRITICAL
- HIGH
- MEDIUM
- LOW

`regex` (required)
:   - Golang regular expression used to detect secrets.

`path` (optional)
:   - Golang regular expression used to match paths.

`keywords` (optional, recommended)
:   - Keywords are used for pre-regex check filtering.
- Rules that contain keywords will perform a quick string compare check to make sure the keyword(s) are in the content being scanned.
- Ideally these values should either be part of the identifier or unique strings specific to the rule's regex.
- It is recommended to define for better performance.

`allow-rules` (optional)
:   - Allow rules for a single rule to reduce false positives with known secrets.
- The details are below.

### Allow Rules
If the detected secret is matched with the specified `regex`, then that secret will be skipped and not detected.
The same logic applies for `path`.

`allow-rules` can be defined globally and per each rule. The fields are the same.

``` yaml
rules:
  - id: rule1
    category: general
    title: Generic Rule
    severity: HIGH
    regex: (?i)(?P<key>(secret))(=|:).{0,5}['"](?P<secret>[0-9a-zA-Z\-_=]{8,64})['"]
    allow-rules:
      - id: skip-text
        description: skip text files
        path: .*\.txt
allow-rules:
  - id: social-security-number
    description: skip social security number
    regex: 219-09-9999
```


`id` (required)
:   - Unique identifier for this allow rule.

`description` (optional)
:   - Short human-readable description of this allow rule.

`regex` (optional)
:   - Golang regular expression used to allow detected secrets.
- `regex` or `path` must be specified.

`path` (optional)
:   - Golang regular expression used to allow matched paths.
- `regex` or `path` must be specified.

### Enable Rules
Trivy provides plenty of out-of-box rules and allow rules, but you may not need all of them.
In that case, `enable-builtin-rules` will be helpful.
If you just need AWS secret detection, you can enable only relevant rules as shown below.
It specifies AWS-related rule IDs in `enable-builtin-rules`.
All other rules are disabled, so the scanning will be much faster.
We would strongly recommend using this option if you don't need all rules.

You can see a full list of [built-in rule IDs][builtin] and [built-in allow rule IDs][builtin-allow].

``` yaml
enable-builtin-rules:
  - aws-access-key-id
  - aws-account-id
  - aws-secret-access-key
```

### Disable Rules
Trivy offers built-in rules and allow rules, but you may want to disable some of them.
For example, you don't use Slack, so Slack doesn't have to be scanned.
You can specify the Slack rule IDs, `slack-access-token` and `slack-web-hook` in `disable-rules` so that those rules will be disabled for less false positives.

You should specify either `enable-builtin-rules` or `disable-rules`.
If they both are specified, `disable-rules` takes precedence.
In case `github-pat` is specified in `enable-builtin-rules` and `disable-rules`, it will be disabled.

In addition, there are some allow rules.
Markdown files are ignored by default, but you may want to scan markdown files as well.
You can disable the allow rule by adding `markdown` to `disable-allow-rules`.

You can see a full list of [built-in rule IDs][builtin] and [built-in allow rule IDs][builtin-allow].

``` yaml
disable-rules:
  - slack-access-token
  - slack-web-hook
disable-allow-rules:
  - markdown
```

## Recommendation
We would recommend specifying `--skip-dirs` for faster secret scanning.
In container image scanning, Trivy walks the file tree rooted  `/` and scans all the files other than [built-in allowed paths][builtin-allow].
It will take a while if your image contains a lot of files even though Trivy tries to avoid scanning layers from a base image.
If you want to make scanning faster, `--skip-dirs` and `--skip-files` helps so that Trivy will skip scanning those files and directories.
You can see more options [here](../configuration/others.md).

`allow-rules` is also helpful. See the [allow-rules](#allow-rules) section.

In addition, all the built-in rules are enabled by default, so it takes some time to scan all of them.
If you don't need all those rules, you can use `enable-builtin-rules` or `disable-rules` in the configuration file.
You should use `enable-builtin-rules` if you need only AWS secret detection, for example.
All rules are disabled except for the ones you specify, so it runs very fast.
On the other hand, you should use `disable-rules` if you just want to disable some built-in rules.
See the [enable-rules](#enable-rules) and [disable-rules](#disable-rules) sections for the detail.

If you don't need secret scanning, you can disable it via the `--scanners` flag.

```shell
$ trivy image --scanners vuln alpine:3.15
```

## Example
`trivy-secret.yaml` in the working directory is loaded by default.

``` yaml
$ cat trivy-secret.yaml
rules:
  - id: rule1
    category: general
    title: Generic Rule
    severity: HIGH
    regex: (?i)(?P<key>(secret))(=|:).{0,5}['"](?P<secret>[0-9a-zA-Z\-_=]{8,64})['"]
allow-rules:
  - id: social-security-number
    description: skip social security number
    regex: 219-09-9999
  - id: log-dir
    description: skip log directory
    path: ^\/var\/log\/
disable-rules:
  - slack-access-token
  - slack-web-hook
disable-allow-rules:
  - markdown

# The following command automatically loads the above configuration.
$ trivy image YOUR_IMAGE
```

Also, you can customize the config file path via `--secret-config`.

``` yaml
$ cat ./secret-config/trivy.yaml
rules:
  - id: rule1
    category: general
    title: Generic Rule
    severity: HIGH
    regex: (?i)(?P<key>(secret))(=|:).{0,5}['"](?P<secret>[0-9a-zA-Z\-_=]{8,64})['"]
    allow-rules:
      - id: skip-text
        description: skip text files
        path: .*\.txt
enable-builtin-rules:
  - aws-access-key-id
  - aws-account-id
  - aws-secret-access-key
disable-allow-rules:
  - usr-dirs

# Pass the above config with `--secret-config`.
$ trivy fs --secret-config ./secret-config/trivy.yaml /path/to/your_project
```

## Credit
This feature is inspired by [gitleaks][gitleaks].

[builtin]: https://github.com/aquasecurity/trivy/blob/{{ git.tag }}/pkg/fanal/secret/builtin-rules.go
[builtin-allow]: https://github.com/aquasecurity/trivy/blob/{{ git.tag }}/pkg/fanal/secret/builtin-allow-rules.go
[gitleaks]: https://github.com/gitleaks/gitleaks

[builtin]: https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/builtin-rules.go
[builtin-allow]: https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/builtin-allow-rules.go
