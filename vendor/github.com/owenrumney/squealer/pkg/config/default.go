package config

func DefaultConfig() *Config {
	return &Config{
		Rules: []MatchRule{
			{
				Rule:        `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
				Description: "Check for AWS Access Key Id",
			},
			{
				Rule:        `(?i)aws_secre.+[=:]\s{0,}[A-Za-z0-9\/+=]{40}.?`,
				Description: "Check for AWS Secret Access Key",
			},
			{
				Rule:        `(?i)github[_\-\.]?token[\s:,="\]']+?(?-i)[0-9a-zA-Z]{35,40}`,
				Description: "Check for Github Token",
			},
			{
				Rule:        `gh[opusr]_[A-Za-z0-9_]{30,255}`,
				Description: "Check for new Github Token",
			},
			{
				Rule:        `xox[baprs]-([0-9a-zA-Z]{10,48})?`,
				Description: "Check for Slack token",
			},
			{
				Rule:        `-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`,
				Description: "Check for Private Asymetric Key",
			},
			{
				Rule:        `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
				Description: "Check for Slack webhook",
			},
			{
				Rule:        `xox.-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}`,
				Description: "Slack API Token",
			},
			{
				Rule:        `xox.-[0-9]{12}-[0-9]{12}-[r0-9a-zA-Z]{24}`,
				Description: "Slack OAuth Token",
			},
			{
				Rule:        `(?im)password\s?[:=]\s?"?.+"?`,
				Description: "Password literal text",
			},
		},
		IgnorePaths: []string{
			"vendor",
			"node_modules",
		},
		IgnoreExtensions: []string{
			".zip",
			".png",
			".jpg",
			".pdf",
			".xls",
			".doc",
			".docx",
		},
		Exceptions: []RuleException{},
	}
}
