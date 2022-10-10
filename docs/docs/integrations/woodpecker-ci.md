# Woodpecker CI

This is a simple example configuration `.woodpecker/trivy.yml` that shows how you could get started:

```yml
pipeline:
  securitycheck:
    image: aquasec/trivy:latest
    commands:
      # use any trivy command, if exit code is 0 woodpecker marks it as passed, else it assumes it failed
      - trivy fs --exit-code 1 --skip-dirs web/ --skip-dirs docs/ --severity MEDIUM,HIGH,CRITICAL .
```

Woodpecker does use Trivy itself so you can see an [Example][example] run at its [Repository][repository] and how it was [added](https://github.com/woodpecker-ci/woodpecker/pull/1163).

[example]: https://ci.woodpecker-ci.org/woodpecker-ci/woodpecker/build/3520/37
[repository]: https://github.com/woodpecker-ci/woodpecker
