# Completion

```bash
To load completions:

Bash:

  $ source <(trivy completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ trivy completion bash > /etc/bash_completion.d/trivy
  # macOS:
  $ trivy completion bash > $(brew --prefix)/etc/bash_completion.d/trivy

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ trivy completion zsh > "${fpath[1]}/_trivy"

  # You will need to start a new shell for this setup to take effect.

fish:

  $ trivy completion fish | source

  # To load completions for each session, execute once:
  $ trivy completion fish > ~/.config/fish/completions/trivy.fish

PowerShell:

  PS> trivy completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> trivy completion powershell > trivy.ps1
  # and source this file from your PowerShell profile.

Usage:
  trivy completion [bash|zsh|fish|powershell]

Flags:
  -h, --help   help for completion

Global Flags:
      --cache-dir string          cache directory (default "/Users/didier/Library/Caches/trivy")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections when using TLS
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```
