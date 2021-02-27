Trivy traversals directories and looks for all lock files by default. If your image contains lock files which are not maintained by you, you can skip the file.

```
$ trivy image --skip-files "/Gemfile.lock,/app/Pipfile.lock" quay.io/fluentd_elasticsearch/fluentd:v2.9.0
```
