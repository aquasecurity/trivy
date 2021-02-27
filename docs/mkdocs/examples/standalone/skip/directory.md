Trivy traversals directories and look for all lock files by default. If your image contains lock files which are not maintained by you, you can skip traversal in the specific directory.

```
$ trivy image --skip-dirs "/usr/lib/ruby/gems,/etc" fluent/fluentd:edge
```
