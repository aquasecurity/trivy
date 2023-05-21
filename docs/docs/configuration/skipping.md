# Skipping Files and Directories

This section details ways to specify the files and directories that Trivy should not scan.

## Skip Files
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

By default, Trivy traverses directories and searches for all necessary files for scanning.
You can skip files that you don't maintain using the `--skip-files` flag.

```
$ trivy image --skip-files "/Gemfile.lock" --skip-files "/var/lib/gems/2.5.0/gems/http_parser.rb-0.6.0/Gemfile.lock" quay.io/fluentd_elasticsearch/fluentd:v2.9.0
```

It's possible to specify globs as part of the value.

```bash
$ trivy image --skip-files "./testdata/*/bar" .
```

Will skip any file named `bar` in the subdirectories of testdata.

## Skip Directories
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |     ✓     |
|     License      |     ✓     |

By default, Trivy traverses directories and searches for all necessary files for scanning.
You can skip directories that you don't maintain using the `--skip-dirs` flag.

```
$ trivy image --skip-dirs /var/lib/gems/2.5.0/gems/fluent-plugin-detect-exceptions-0.0.13 --skip-dirs "/var/lib/gems/2.5.0/gems/http_parser.rb-0.6.0" quay.io/fluentd_elasticsearch/fluentd:v2.9.0
```

It's possible to specify globs as part of the value.

```bash
$ trivy image --skip-dirs "./testdata/*" .
```

Will skip all subdirectories of the testdata directory.

!!! tip
    Glob patterns work with any trivy subcommand (image, config, etc.) and can be specified to skip both directories (with `--skip-dirs`) and files (with `--skip-files`).


### Advanced globbing
Trivy also supports the [globstar](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html#Pattern-Matching) pattern matching. 

```bash
$ trivy image --skip-files "**/foo" image:tag
```

Will skip the file `foo` that happens to be nested under any parent(s). 

## File patterns
|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |     ✓     |
|      Secret      |           |
|     License      |           |

When a directory is given as an input, Trivy will recursively look for and test all files based on file patterns.
The default file patterns are [here](../scanner/misconfiguration/custom/index.md).

In addition to the default file patterns, the `--file-patterns` option takes regexp patterns to look for your files.
For example, it may be useful when your file name of Dockerfile doesn't match the default patterns.

This can be repeated for specifying multiple file patterns.

A file pattern contains the analyzer it is used for, and the pattern itself, joined by a semicolon. For example:
```
--file-patterns "dockerfile:.*.docker" --file-patterns "kubernetes:*.tpl" --file-patterns "pip:requirements-.*\.txt"
```

The prefixes are listed [here](https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/pkg/fanal/analyzer/const.go)
