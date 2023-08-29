# Enable shell completion

Below is example steps to enable shell completion feature for `trivy` cli:

### 1. Know your current shell

```bash
$ echo $SHELL
/bin/zsh # For this example it is zsh, but will be vary depend on your $SHELL, maybe /bin/bash or /bin/fish
```

### 2. Run `completion` command to get sub-commands

``` bash
$ trivy completion zsh -h
Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(trivy completion zsh); compdef _trivy trivy

To load completions for every new session, execute once:

#### Linux:

	trivy completion zsh > "${fpath[1]}/_trivy"

#### macOS:

	trivy completion zsh > $(brew --prefix)/share/zsh/site-functions/_trivy

You will need to start a new shell for this setup to take effect.
```

### 3. Run the sub-commands following the instruction

```bash
echo "autoload -U compinit; compinit" >> ~/.zshrc
source <(trivy completion zsh); compdef _trivy trivy
trivy completion zsh > "${fpath[1]}/_trivy"
```

### 4. Start a new shell and you can see the shell completion

```bash
$ trivy [tab]
aws         -- scan aws account
completion  -- Generate the autocompletion script for the specified shell
config      -- Scan config files for misconfigurations
filesystem  -- Scan local filesystem
help        -- Help about any command
image       -- Scan a container image
kubernetes  -- scan kubernetes cluster
module      -- Manage modules
plugin      -- Manage plugins
repository  -- Scan a repository
rootfs      -- Scan rootfs
sbom        -- Scan SBOM for vulnerabilities
server      -- Server mode
version     -- Print the version
```