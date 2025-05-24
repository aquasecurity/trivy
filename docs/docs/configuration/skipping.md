# Selecting files for scanning

When scanning a target (image, code repository, etc), Trivy traverses all directories and files in that target and looks for known files to scan. For example, vulnerability scanner might look for `/lib/apk/db/installed` for Alpine APK scanning or `requirements.txt` file for Python pip scanning, and misconfiguration scanner might look for `Dockerfile` for Dockerfile scanning. This document explains how to control which files Trivy looks (including skipping files) for and how it should process them.

!!! note
    Selecting/skipping files is different from filtering/ignoring results, which is covered in the [Filtering document](./filtering.md)

## Skip Files and Directories

You can skip specific files and directories using the `--skip-files` and `--skip-dirs` flags.

For example:

```bash
trivy image --skip-files "/Gemfile.lock" --skip-dirs "/var/lib/gems/2.5.0/gems/http_parser.rb-0.6.0" quay.io/fluentd_elasticsearch/fluentd:v2.9.0
```

This feature is relevant for the following scanners:

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

It's possible to specify glob patterns when referring to a file or directory. The glob expression follows the ["doublestar" library syntax](https://pkg.go.dev/github.com/bmatcuk/doublestar/v4@v4.8.1#readme-patterns).

Examples:

```bash
# skip any file named `bar` in the subdirectories of testdata
trivy image --skip-files "./testdata/*/bar" .
```

```bash
# skip any files with the extension `.tf` in subdirectories of foo at any depth
trivy config --skip-files "./foo/**/*.tf" .
```

```bash
# skip all subdirectories of the testdata directory.
trivy image --skip-dirs "./testdata/*" .
```

```bash
# skip subdirectories at any depth named `.terraform/`. 
# this will match `./foo/.terraform` or `./foo/bar/.terraform`, but not `./.terraform`
trivy config --skip-dirs "**/.terraform" .
```

Like any other flag, this is available as Trivy YAML configuration.

For example:

```yaml
image:
  skip-files:
    - foo
    - "testdata/*/bar"
  skip-dirs:
    - foo/bar/
    - "**/.terraform"
```

## Customizing file handling

You can customize which files Trivy scans and how it interprets them with the `--file-patterns` flag.
A file pattern configuration takes the following form: `<analyzer>:<path>`, such that files matching the `<path>` will be processed with the respective `<analyzer>`.

For example:

```bash
trivy fs --file-patterns "pip:.requirements-test.txt ."
```

This feature is relevant for the following scanners:

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |           |
|     License      |   ✓[^1]   |

!!!note
    This flag is not applicable for parsers that accepts multiple files, for example the Terraform file parser which loads all `.tf` files into state.

The list of analyzers can be found [here](https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/pkg/fanal/analyzer/const.go)

The file path can use a [regular expression](https://pkg.go.dev/regexp/syntax). For example:

```bash
# interpret any file with .txt extension as a python pip requirements file
trivy fs --file-patterns "pip:requirements-.*\.txt .
```

The flag can be repeated for specifying multiple file patterns. For example:

```bash
# look for Dockerfile called production.docker and a python pip requirements file called requirements-test.txt
trivy fs --scanners misconfig,vuln --file-patterns "dockerfile:.production.docker" --file-patterns "pip:.requirements-test.txt ."
```

[^1]: Only work with the [license-full](../scanner/license.md) flag

## Avoid full filesystem traversal

In specific scenarios Trivy can avoid traversing the entire filesystem, which makes scanning faster and more efficient.
For more information see [here](../target/rootfs.md#performance-optimization)
