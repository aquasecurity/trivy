# Configuration
Trivy tries to load `trivy-secret.yaml` in the current directory by default.
If the file doesn't exist, only builtin rules are used.
You can customize the config file name via the `--secret-config` flag.

## Custom Rules
Trivy allows defining custom rules. You can see an example.

``` yaml
rules:
  - id: rule1
    category: general
    title: Generic Rule
    severity: HIGH
    path:
      - .*\.sh
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

## Allow Rules
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

## Disable Rules
Trivy offers builtin rules and allow rules, but you may want to disable some of them.
For example, you don't use Slack, so Slack doesn't have to be scanned.
You can specify `slack-access-token` and `slack-web-hook` in `disable-rules` so that those rules will be disabled for less false positives.

Markdown files are ignored by default, but you may want to scan markdown files as well.
You can disable the allow list by adding `markdown` to `disable-allow-rules`.

You can see a full list of rule IDs [here][builtin]. Allow rule IDs are below in the file.

``` yaml
disable-rules:
  - slack-access-token
  - slack-web-hook
disable-allow-rules:
  - markdown
```

## Example

``` yaml
$ cat trivy-secret.yaml
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
disable-rules:
  - slack-access-token
  - slack-web-hook
disable-allow-rules:
  - markdown
```

[builtin]: https://github.com/aquasecurity/fanal/blob/main/secret/builtin.go
