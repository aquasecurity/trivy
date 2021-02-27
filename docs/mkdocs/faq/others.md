### GitHub Rate limiting

Specify GITHUB_TOKEN for authentication
https://developer.github.com/v3/#rate-limiting

```
$ GITHUB_TOKEN=XXXXXXXXXX trivy alpine:3.10
```

### Unknown error

Try again with `--reset` option:

```
$ trivy image --reset
```
