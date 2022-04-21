# Filesystem
Trivy scans any repository or filesystem to detect exposed secrets.
Secret scanning is enabled by default when using the `filesystem` subcommand.
Any plaintext file in the repository or filesystem will be scanned.
### Local project 
You can run a scan of a project or directory using the following command.

```bash
$ trivy fs /path/to/project
```


### Single file
It's also possible to scan a single file.
```bash
$ trivy fs ~/src/github.com/aquasecurity/trivy-db/pkg/db/db.go
```

