# Skip Files/Directories

## Skip Files
Trivy traversals directories and looks for all lock files by default.
If your image contains lock files which are not maintained by you, you can skip the file.

```
$ trivy image --skip-files "/Gemfile.lock,/app/Pipfile.lock" quay.io/fluentd_elasticsearch/fluentd:v2.9.0
```

## Skip Directories
Trivy traversals directories and look for all lock files by default.
If your image contains lock files which are not maintained by you, you can skip traversal in the specific directory.

```
$ trivy image --skip-dirs "/usr/lib/ruby/gems,/etc" fluent/fluentd:edge
```
