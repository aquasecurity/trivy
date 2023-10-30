# Filtering
Trivy provides various methods for filtering the results.


## By Status

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |           |
|      Secret      |           |
|     License      |           |

Trivy supports the following vulnerability statuses:

- `unknown`
- `not_affected`: this package is not affected by this vulnerability on this platform
- `affected`: this package is affected by this vulnerability on this platform, but there is no patch released yet
- `fixed`: this vulnerability is fixed on this platform
- `under_investigation`: it is currently unknown whether or not this vulnerability affects this package on this platform, and it is under investigation
- `will_not_fix`: this package is affected by this vulnerability on this platform, but there is currently no intention to fix it (this would primarily be for flaws that are of Low or Moderate impact that pose no significant risk to customers)
- `fix_deferred`: this package is affected by this vulnerability on this platform, and may be fixed in the future
- `end_of_life`: this package has been identified to contain the impacted component, but analysis to determine whether it is affected or not by this vulnerability was not performed

Note that vulnerabilities with the `unknown`, `not_affected` or `under_investigation` status are not detected.
These are only defined for comprehensiveness, and you will not have the opportunity to specify these statuses.

Some statuses are supported in limited distributions.

|     OS     | Fixed | Affected | Under Investigation | Will Not Fix | Fix Deferred | End of Life |
|:----------:|:-----:|:--------:|:-------------------:|:------------:|:------------:|:-----------:|
|   Debian   |   ✓   |    ✓     |                     |              |      ✓       |      ✓      |
|    RHEL    |   ✓   |    ✓     |          ✓          |      ✓       |      ✓       |      ✓      |
| Other OSes |   ✓   |    ✓     |                     |              |              |             |


To ignore vulnerabilities with specific statuses, use the `--ignore-status <list_of_statuses>` option.


```bash
$ trivy image --ignore-status affected,fixed ruby:2.4.0
```

<details>
<summary>Result</summary>

```
2019-05-16T12:50:14.786+0900    INFO    Detecting Debian vulnerabilities...

ruby:2.4.0 (debian 8.7)
=======================
Total: 527 (UNKNOWN: 0, LOW: 276, MEDIUM: 83, HIGH: 158, CRITICAL: 10)

┌─────────────────────────────┬──────────────────┬──────────┬──────────────┬────────────────────────────┬───────────────┬──────────────────────────────────────────────────────────────┐
│           Library           │  Vulnerability   │ Severity │    Status    │     Installed Version      │ Fixed Version │                            Title                             │
├─────────────────────────────┼──────────────────┼──────────┼──────────────┼────────────────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ binutils                    │ CVE-2014-9939    │ CRITICAL │ will_not_fix │ 2.25-5                     │               │ binutils: buffer overflow in ihex.c                          │
│                             │                  │          │              │                            │               │ https://avd.aquasec.com/nvd/cve-2014-9939                    │
│                             ├──────────────────┤          │              │                            ├───────────────┼──────────────────────────────────────────────────────────────┤
│                             │ CVE-2017-6969    │          │              │                            │               │ binutils: Heap-based buffer over-read in readelf when        │
│                             │                  │          │              │                            │               │ processing corrupt RL78 binaries                             │
│                             │                  │          │              │                            │               │ https://avd.aquasec.com/nvd/cve-2017-6969                    │
│                             ├──────────────────┤          │              │                            ├───────────────┼──────────────────────────────────────────────────────────────┤
...
```

</details>

!!! tip
    To skip all unfixed vulnerabilities, you can use the `--ignore-unfixed` flag .
    It is a shorthand of `--ignore-status affected,will_not_fix,fix_deferred,end_of_life`.
    It displays "fixed" vulnerabilities only.

```bash
$ trivy image --ignore-unfixed ruby:2.4.0
```

## By Severity

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

Use `--severity` option.

```bash
$ trivy image --severity HIGH,CRITICAL ruby:2.4.0
```

<details>
<summary>Result</summary>

```bash
2019-05-16T01:51:46.255+0900    INFO    Updating vulnerability database...
2019-05-16T01:51:49.213+0900    INFO    Detecting Debian vulnerabilities...

ruby:2.4.0 (debian 8.7)
=======================
Total: 1785 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1680, CRITICAL: 105)

+-----------------------------+------------------+----------+---------------------------+----------------------------------+-------------------------------------------------+
|           LIBRARY           | VULNERABILITY ID | SEVERITY |     INSTALLED VERSION     |          FIXED VERSION           |                      TITLE                      |
+-----------------------------+------------------+----------+---------------------------+----------------------------------+-------------------------------------------------+
| apt                         | CVE-2019-3462    | CRITICAL | 1.0.9.8.3                 | 1.0.9.8.5                        | Incorrect sanitation of the                     |
|                             |                  |          |                           |                                  | 302 redirect field in HTTP                      |
|                             |                  |          |                           |                                  | transport method of...                          |
+-----------------------------+------------------+----------+---------------------------+----------------------------------+-------------------------------------------------+
| bash                        | CVE-2019-9924    | HIGH     | 4.3-11                    | 4.3-11+deb8u2                    | bash: BASH_CMD is writable in                   |
|                             |                  |          |                           |                                  | restricted bash shells                          |
+                             +------------------+          +                           +----------------------------------+-------------------------------------------------+
|                             | CVE-2016-7543    |          |                           | 4.3-11+deb8u1                    | bash: Specially crafted                         |
|                             |                  |          |                           |                                  | SHELLOPTS+PS4 variables allows                  |
|                             |                  |          |                           |                                  | command substitution                            |
+-----------------------------+------------------+          +---------------------------+----------------------------------+-------------------------------------------------+
| binutils                    | CVE-2017-8421    |          | 2.25-5                    |                                  | binutils: Memory exhaustion in                  |
|                             |                  |          |                           |                                  | objdump via a crafted PE file                   |
+                             +------------------+          +                           +----------------------------------+-------------------------------------------------+
|                             | CVE-2017-14930   |          |                           |                                  | binutils: Memory leak in                        |
|                             |                  |          |                           |                                  | decode_line_info                                |
+                             +------------------+          +                           +----------------------------------+-------------------------------------------------+
|                             | CVE-2017-7614    |          |                           |                                  | binutils: NULL                                  |
|                             |                  |          |                           |                                  | pointer dereference in                          |
|                             |                  |          |                           |                                  | bfd_elf_final_link function                     |
+                             +------------------+          +                           +----------------------------------+-------------------------------------------------+
|                             | CVE-2014-9939    |          |                           |                                  | binutils: buffer overflow in                    |
|                             |                  |          |                           |                                  | ihex.c                                          |
+                             +------------------+          +                           +----------------------------------+-------------------------------------------------+
|                             | CVE-2017-13716   |          |                           |                                  | binutils: Memory leak with the                  |
|                             |                  |          |                           |                                  | C++ symbol demangler routine                    |
|                             |                  |          |                           |                                  | in libiberty                                    |
+                             +------------------+          +                           +----------------------------------+-------------------------------------------------+
|                             | CVE-2018-12699   |          |                           |                                  | binutils: heap-based buffer                     |
|                             |                  |          |                           |                                  | overflow in finish_stab in                      |
|                             |                  |          |                           |                                  | stabs.c                                         |
+-----------------------------+------------------+          +---------------------------+----------------------------------+-------------------------------------------------+
| bsdutils                    | CVE-2015-5224    |          | 2.25.2-6                  |                                  | util-linux: File name                           |
|                             |                  |          |                           |                                  | collision due to incorrect                      |
|                             |                  |          |                           |                                  | mkstemp use                                     |
+                             +------------------+          +                           +----------------------------------+-------------------------------------------------+
|                             | CVE-2016-2779    |          |                           |                                  | util-linux: runuser tty hijack                  |
|                             |                  |          |                           |                                  | via TIOCSTI ioctl                               |
+-----------------------------+------------------+----------+---------------------------+----------------------------------+-------------------------------------------------+
```

</details>

```bash
trivy conf --severity HIGH,CRITICAL examples/misconf/mixed
```

<details>
<summary>Result</summary>

```shell
2022-05-16T13:50:42.718+0100	INFO	Detected config files: 3

Dockerfile (dockerfile)
=======================
Tests: 17 (SUCCESSES: 16, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

HIGH: Last USER command in Dockerfile should not be 'root'
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Dockerfile:3
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   3 [ USER root
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



deployment.yaml (kubernetes)
============================
Tests: 8 (SUCCESSES: 8, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (HIGH: 0, CRITICAL: 0)


main.tf (terraform)
===================
Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 0, CRITICAL: 1)

CRITICAL: Classic resources should not be used.
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.

See https://avd.aquasec.com/misconfig/avd-aws-0081
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 main.tf:2-4
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   2 ┌ resource "aws_db_security_group" "sg" {
   3 │
   4 └ }
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
</details>

## By Finding IDs

Trivy supports the [.trivyignore](#trivyignore) and [.trivyignore.yaml](#trivyignoreyaml) ignore files.

### .trivyignore

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |           |


```bash
$ cat .trivyignore
# Accept the risk
CVE-2018-14618

# Accept the risk until 2023-01-01
CVE-2019-14697 exp:2023-01-01

# No impact in our settings
CVE-2019-1543

# Ignore misconfigurations
AVD-DS-0002

# Ignore secrets
generic-unwanted-rule
aws-account-id
```

```bash
$ trivy image python:3.4-alpine3.9
```

<details>
<summary>Result</summary>

```bash
2019-05-16T12:53:10.076+0900    INFO    Updating vulnerability database...
2019-05-16T12:53:28.134+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

```

</details>

### .trivyignore.yaml

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

When the extension of the specified ignore file is either `.yml` or `.yaml`, Trivy will load the file as YAML.
For the `.trivyignore.yaml` file, you can set ignored IDs separately for `vulnerabilities`, `misconfigurations`, `secrets`, or `licenses`[^1].

Available fields:

| Field      | Required | Type                | Description                                                                                                |
|------------|:--------:|---------------------|------------------------------------------------------------------------------------------------------------|
| id         |    ✓     | string              | The identifier of the vulnerability, misconfiguration, secret, or license[^1].                             |
| paths      |          | string array        | The list of file paths to be ignored. If `paths` is not set, the ignore finding is applied to all files.   |
| expired_at |          | date (`yyyy-mm-dd`) | The expiration date of the ignore finding. If `expired_at` is not set, the ignore finding is always valid. |
| statement  |          | string              | The reason for ignoring the finding. (This field is not used for filtering.)                               |

```bash
$ cat .trivyignore.yaml
vulnerabilities:
  - id: CVE-2022-40897
    paths:
      - "usr/local/lib/python3.9/site-packages/setuptools-58.1.0.dist-info/METADATA"
    statement: Accept the risk
  - id: CVE-2023-2650
  - id: CVE-2023-3446
  - id: CVE-2023-3817
  - id: CVE-2023-29491
    expired_at: 2023-09-01

misconfigurations:
  - id: AVD-DS-0001
  - id: AVD-DS-0002
    paths:
      - "docs/Dockerfile"
    statement: The image needs root privileges

secrets:
  - id: aws-access-key-id
  - id: aws-secret-access-key
    paths:
      - "foo/bar/aws.secret"

licenses:
  - id: GPL-3.0 # License name is used as ID
    paths:
      - "usr/share/gcc/python/libstdcxx/v6/__init__.py"
```

Since this feature is experimental, you must explicitly specify the YAML file path using the `--ignorefile` flag.
Once this functionality is stable, the YAML file will be loaded automatically.

```bash
$ trivy image --ignorefile ./.trivyignore.yaml python:3.9.16-alpine3.16
```

<details>
<summary>Result</summary>

```bash
2023-08-31T11:10:27.155+0600	INFO	Vulnerability scanning is enabled
2023-08-31T11:10:27.155+0600	INFO	Secret scanning is enabled
2023-08-31T11:10:27.155+0600	INFO	If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2023-08-31T11:10:27.155+0600	INFO	Please see also https://aquasecurity.github.io/trivy/dev/docs/scanner/secret/#recommendation for faster secret detection
2023-08-31T11:10:29.164+0600	INFO	Detected OS: alpine
2023-08-31T11:10:29.164+0600	INFO	Detecting Alpine vulnerabilities...
2023-08-31T11:10:29.169+0600	INFO	Number of language-specific files: 1
2023-08-31T11:10:29.170+0600	INFO	Detecting python-pkg vulnerabilities...

python:3.9.16-alpine3.16 (alpine 3.16.5)
========================================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


```

</details>


## By Vulnerability Target
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |           |
|      Secret      |           |
|     License      |           |

Use `--vuln-type` option.

```bash
$ trivy image --vuln-type os ruby:2.4.0
```

Available values:

- library
- os

<details>
<summary>Result</summary>

```bash
2019-05-22T19:36:50.530+0200    [34mINFO[0m    Updating vulnerability database...
2019-05-22T19:36:51.681+0200    [34mINFO[0m    Detecting Alpine vulnerabilities...
2019-05-22T19:36:51.685+0200    [34mINFO[0m    Updating npm Security DB...
2019-05-22T19:36:52.389+0200    [34mINFO[0m    Detecting npm vulnerabilities...
2019-05-22T19:36:52.390+0200    [34mINFO[0m    Updating pipenv Security DB...
2019-05-22T19:36:53.406+0200    [34mINFO[0m    Detecting pipenv vulnerabilities...

ruby:2.4.0 (debian 8.7)
=======================
Total: 7 (UNKNOWN: 0, LOW: 1, MEDIUM: 1, HIGH: 3, CRITICAL: 2)

+---------+------------------+----------+-------------------+---------------+----------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |              TITLE               |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| curl    | CVE-2018-14618   | CRITICAL | 7.61.0-r0         | 7.61.1-r0     | curl: NTLM password overflow     |
|         |                  |          |                   |               | via integer overflow             |
+         +------------------+----------+                   +---------------+----------------------------------+
|         | CVE-2018-16839   | HIGH     |                   | 7.61.1-r1     | curl: Integer overflow leading   |
|         |                  |          |                   |               | to heap-based buffer overflow in |
|         |                  |          |                   |               | Curl_sasl_create_plain_message() |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| git     | CVE-2018-17456   | HIGH     | 2.15.2-r0         | 2.15.3-r0     | git: arbitrary code execution    |
|         |                  |          |                   |               | via .gitmodules                  |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2018-19486   |          |                   |               | git: Improper handling of        |
|         |                  |          |                   |               | PATH allows for commands to be   |
|         |                  |          |                   |               | executed from...                 |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| libssh2 | CVE-2019-3855    | CRITICAL | 1.8.0-r2          | 1.8.1-r0      | libssh2: Integer overflow in     |
|         |                  |          |                   |               | transport read resulting in      |
|         |                  |          |                   |               | out of bounds write...           |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| sqlite  | CVE-2018-20346   | MEDIUM   | 3.21.0-r1         | 3.25.3-r0     | CVE-2018-20505 CVE-2018-20506    |
|         |                  |          |                   |               | sqlite: Multiple flaws in        |
|         |                  |          |                   |               | sqlite which can be triggered    |
|         |                  |          |                   |               | via...                           |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| tar     | CVE-2018-20482   | LOW      | 1.29-r1           | 1.31-r0       | tar: Infinite read loop in       |
|         |                  |          |                   |               | sparse_dump_region function in   |
|         |                  |          |                   |               | sparse.c                         |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
```

</details>

## By Open Policy Agent

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |           |
|     License      |           |

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy supports Open Policy Agent (OPA) to filter vulnerabilities.
You can specify a Rego file with `--ignore-policy` option.

The Rego package name must be `trivy` and it must include a rule called `ignore` which determines if each individual vulnerability should be excluded (ignore=true) or not (ignore=false). In the policy, each vulnerability will be available for inspection as the `input` variable. The structure of each vulnerability input is the same as for the Trivy JSON output.  
There is a built-in Rego library with helper functions that you can import into your policy using: `import data.lib.trivy`. For more info about the helper functions, look at the library [here][helper]

To get started, see the [example policy][policy].

```bash
$ trivy image --ignore-policy contrib/example_policy/basic.rego centos:7
```

<details>
<summary>Result</summary>

```bash
centos:7 (centos 7.9.2009)
==========================
Total: 9 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 4, CRITICAL: 5)

+--------------+------------------+----------+-------------------+-------------------+-----------------------------------------+
|   LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |   FIXED VERSION   |                  TITLE                  |
+--------------+------------------+----------+-------------------+-------------------+-----------------------------------------+
| glib2        | CVE-2015-8385    | HIGH     | 2.56.1-7.el7      |                   | pcre: buffer overflow caused            |
|              |                  |          |                   |                   | by named forward reference              |
|              |                  |          |                   |                   | to duplicate group number...            |
|              |                  |          |                   |                   | -->avd.aquasec.com/nvd/cve-2015-8385    |
+              +------------------+          +                   +-------------------+-----------------------------------------+
|              | CVE-2016-3191    |          |                   |                   | pcre: workspace overflow for            |
|              |                  |          |                   |                   | (*ACCEPT) with deeply nested            |
|              |                  |          |                   |                   | parentheses (8.39/13, 10.22/12)         |
|              |                  |          |                   |                   | -->avd.aquasec.com/nvd/cve-2016-3191    |
+              +------------------+          +                   +-------------------+-----------------------------------------+
|              | CVE-2021-27219   |          |                   | 2.56.1-9.el7_9    | glib: integer overflow in               |
|              |                  |          |                   |                   | g_bytes_new function on                 |
|              |                  |          |                   |                   | 64-bit platforms due to an...           |
|              |                  |          |                   |                   | -->avd.aquasec.com/nvd/cve-2021-27219   |
+--------------+------------------+----------+-------------------+-------------------+-----------------------------------------+
| glibc        | CVE-2019-1010022 | CRITICAL | 2.17-317.el7      |                   | glibc: stack guard protection bypass    |
|              |                  |          |                   |                   | -->avd.aquasec.com/nvd/cve-2019-1010022 |
+--------------+                  +          +                   +-------------------+                                         +
| glibc-common |                  |          |                   |                   |                                         |
|              |                  |          |                   |                   |                                         |
+--------------+------------------+          +-------------------+-------------------+-----------------------------------------+
| nss          | CVE-2021-43527   |          | 3.53.1-3.el7_9    | 3.67.0-4.el7_9    | nss: Memory corruption in               |
|              |                  |          |                   |                   | decodeECorDsaSignature with             |
|              |                  |          |                   |                   | DSA signatures (and RSA-PSS)            |
|              |                  |          |                   |                   | -->avd.aquasec.com/nvd/cve-2021-43527   |
+--------------+                  +          +                   +                   +                                         +
| nss-sysinit  |                  |          |                   |                   |                                         |
|              |                  |          |                   |                   |                                         |
|              |                  |          |                   |                   |                                         |
|              |                  |          |                   |                   |                                         |
+--------------+                  +          +                   +                   +                                         +
| nss-tools    |                  |          |                   |                   |                                         |
|              |                  |          |                   |                   |                                         |
|              |                  |          |                   |                   |                                         |
|              |                  |          |                   |                   |                                         |
+--------------+------------------+----------+-------------------+-------------------+-----------------------------------------+
| openssl-libs | CVE-2020-1971    | HIGH     | 1:1.0.2k-19.el7   | 1:1.0.2k-21.el7_9 | openssl: EDIPARTYNAME                   |
|              |                  |          |                   |                   | NULL pointer de-reference               |
|              |                  |          |                   |                   | -->avd.aquasec.com/nvd/cve-2020-1971    |
+--------------+------------------+----------+-------------------+-------------------+-----------------------------------------+
```

</details>

[helper]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/pkg/result/module.go
[policy]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/contrib/example_policy

## By Inline Comments

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |           |
| Misconfiguration |     ✓     |
|      Secret      |           |
|     License      |           |

Some configuration file formats (e.g. Terraform) support inline comments.

In cases where trivy can detect comments of a specific format immediately adjacent to resource definitions, it is possible to filter/ignore findings from a single point of resource definition (in contrast to `.trivyignore`, which has a directory-wide scope on all of the files scanned).

The format for these comments is `trivy:ignore:<Vulnerability ID>` immediately following the format-specific line-comment token.

For example, to filter a Vulnerability ID "AVD-GCP-0051" in a Terraform HCL file:

```terraform
#trivy:ignore:AVD-GCP-0051
resource "google_container_cluster" "one_off_test" {
  name     = var.cluster_name
  location = var.region
}
```

[^1]: license name is used as id for `.trivyignore.yaml` files
