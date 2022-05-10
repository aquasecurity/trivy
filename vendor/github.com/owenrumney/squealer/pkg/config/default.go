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
				Rule:        `(?im)password\s?[:=]\s?"?[^\s?\$\{].+"?`,
				Description: "Password literal text",
			},
			{
				Description: "AWS Manager ID",
				Rule:        `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
			},
			{
				Description: "AWS Manager ID",
				Rule:        `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
			},
			{
				Description: "AWS Secret Key",
				Rule:        `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`,
			},
			{
				Description: "AWS MWS key",
				Rule:        `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			},
			{
				Description: "Facebook Secret Key",
				Rule:        `(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]`,
			},
			{
				Description: "Facebook Client ID",
				Rule:        `(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]`,
			},
			{
				Description: "Twitter Secret Key",
				Rule:        `(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]`,
			},
			{
				Description: "Twitter Client ID",
				Rule:        `(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]`,
			},
			{
				Description: "Github",
				Rule:        `(?i)github.{0,3}((?i)token|api|key).{0,10}?(?-i)([0-9a-zA-Z]{35,40})`,
			},
			{
				Description: "LinkedIn Client ID",
				Rule:        `(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]`,
			},
			{
				Description: "LinkedIn Secret Key",
				Rule:        `(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]`,
			},
			{
				Description: "NPM Token",
				Rule:        `//registry.npmjs.org/:_authToken=[0-9a-f-]+`,
			},
			{
				Description: "Slack",
				Rule:        `xox[baprs]-([0-9a-zA-Z]{10,48})?`,
			},
			{
				Description: "EC",
				Rule:        `-----BEGIN EC PRIVATE KEY-----`,
			},
			{
				Description: "DSA",
				Rule:        `-----BEGIN DSA PRIVATE KEY-----`,
			},
			{
				Description: "OPENSSH",
				Rule:        `-----BEGIN OPENSSH PRIVATE KEY-----`,
			},
			{
				Description: "RSA",
				Rule:        `-----BEGIN RSA PRIVATE KEY-----`,
			},
			{
				Description: "PGP",
				Rule:        `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			},
			{
				Description: "Google API key",
				Rule:        `AIza[0-9A-Za-z\\-_]{35}`,
			},
			{
				Description: "Heroku API key",
				Rule:        `(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]`,
			},
			{
				Description: "MailChimp API key",
				Rule:        `(?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]`,
			},
			{
				Description: "Mailgun API key",
				Rule:        `(?i)(mailgun|mg)(.{0,20})?['"][0-9a-z]{32}['"]`,
			},
			{
				Description: "PayPal Braintree access token",
				Rule:        `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
			},
			{
				Description: "Picatic API key",
				Rule:        `sk_live_[0-9a-z]{32}`,
			},
			{
				Description: "Slack Webhook",
				Rule:        `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
			},
			{
				Description: "Stripe API key",
				Rule:        `(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24}`,
			},
			{
				Description: "Square access token",
				Rule:        `sq0atp-[0-9A-Za-z\-_]{22}`,
			},
			{
				Description: "Square OAuth secret",
				Rule:        `sq0csp-[0-9A-Za-z\\-_]{43}`,
			},
			{
				Description: "Twilio API key",
				Rule:        `(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]`,
			},
			{
				Description: "Dynatrace token",
				Rule:        `dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}`,
			},
			{
				Description: "Shopify shared secret",
				Rule:        `shpss_[a-fA-F0-9]{32}`,
			},
			{
				Description: "Shopify access token",
				Rule:        `shpat_[a-fA-F0-9]{32}`,
			},
			{
				Description: "Shopify custom app access token",
				Rule:        `shpca_[a-fA-F0-9]{32}`,
			},
			{
				Description: "Shopify private app access token",
				Rule:        `shppa_[a-fA-F0-9]{32}`,
			},
			{
				Description: "Env Var",
				Rule:        `(?i)(apikey|secret|password|certificate_osx_p12|certificate_password|codacy_project_token|coveralls_api_token|coveralls_repo_token|coveralls_token|coverity_scan_token|cypress_record_key|database_password|db_password|deploy_password|deploy_token|digitalocean_access_token|docker_hub_password|docker_password|dockerhub_password|sonatype_password|firebase_api_token|firebase_token|firefox_secret|flask_secret_key|fossa_api_key|gcloud_service_key|gcr_password|gh_api_key|gh_next_oauth_client_secret|gh_next_unstable_oauth_client_secret|gh_oauth_client_secret|gpg_private_key|gpg_passphrase|gpg_secret_keys|heroku_api_key|okta_client_token|pypi_password|sonatype_nexus_password|travis_token|refresh_token|client_id|client_secret)(.*)?[(:=](\s)?['\"][0-9a-zA-Z-_!$^%=]{10,120}['\")]`,
				Entropy:     "4.2,7.0",
			},
			{
				Description: "Static key",
				Rule:        `(?i)(cookieParser)(.*)?[(](\s)?['\"][0-9a-zA-Z-_!$^%=]{5,20}['\")]`,
				FileFilter:  `\.(js|ts)$`,
			},
			{
				Description: "WP-Config",
				Rule:        `define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|"].{10,120}['|"]`,
			},
			{
				Description: "Shell history",
				Rule:        `.`,
				FileFilter:  `\.?(bash_|zsh_|z|mysql_|psql_|irb_)?history$`,
			},
			{
				Description: "Postgres password",
				Rule:        `.`,
				FileFilter:  `\.pgpass$`,
			},
			{
				Description: "OpenVPN",
				Rule:        `.`,
				FileFilter:  `\.ovpn$`,
			},
			{
				Description: "Unknown Key",
				Rule:        `.`,
				FileFilter:  `\.key$`,
			},
			{
				Description: "Keychain file",
				Rule:        `.`,
				FileFilter:  `\.(kdb|agilekeychain|keychain|kwallet|git-credentials|proftpdpasswd|dockercfg|credentials)$`,
			},
			{
				Description: "s3cfg",
				Rule:        `.`,
				FileFilter:  `\.s3cfg$`,
			},
			{
				Description: "secret token",
				Rule:        `.`,
				FileFilter:  `(omniauth|secret_token|carrierwave)\.rb$`,
			},
			{
				Description: "GitCredential",
				Rule:        `https?://.+:.+@.*`,
				FileFilter:  `\.gitCredentials$`,
			},
			{
				Description: "KeyStoreFile",
				Rule:        `.`,
				FileFilter:  `\.keystore$`,
			},
			{
				Description: "Base64EncodedCertificateInCode",
				Rule:        `['">;=]MII[a-z0-9/+]{200}`,
				FileFilter:  `\.(?:cs|ini|json|ps1|publishsettings|template|trd|ts|xml)$`,
			},
			{
				Description: "Base64EncodedCertificateInFile",
				Rule:        `MII[A-Za-z0-9/+]{60}`,
				FileFilter:  `\.(?:cert|cer)$`,
			},
			{
				Description: "PublishSettings",
				Rule:        `userPWD="[a-zA-Z0-9\+\/]{60}"`,
				FileFilter:  `(?i)(publishsettings|\.pubxml$)`,
			},
			{
				Description: "PemFile 1",
				FileFilter:  `\.pem$`,
				Rule:        `-{5}BEGIN(?: (?:[dr]sa|ec|openssh))? PRIVATE KEY-{5}`,
			},
			{
				Description: "AspNetMachineKeyInConfig 1",
				FileFilter:  `\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `<machineKey[^>]+(?:decryptionKey\s*\=\s*"[a-fA-F0-9]{48,}|validationKey\s*\=\s*"[a-fA-F0-9]{48,})[^>]+>`,
			},
			{
				Description: "AspNetMachineKeyInConfig 2",
				FileFilter:  `\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `(?:decryptionKey|validationKey)="[a-zA-Z0-9]+"`,
			},
			{
				Description: "SqlConnectionStringInConfig 1",
				FileFilter:  `\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `(?i)(?:connection[sS]tring|connString)[^=]*=["'][^"']*[pP]assword\s*=\s*[^\s;][^"']*(?:'|")`,
			},
			{
				Description: "SqlConnectionStringInConfig 2 / CSCAN0043 SqlConnectionStringInCode",
				FileFilter:  `\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties|policy_and_key\.hpp|AccountConfig\.h)$|hubot`,
				Rule:        `(?i)(?:User ID|uid|UserId).*(?:Password|[^a-z]pwd)=[^'\$%<@'";\[\{][^;/"]{4,128}(?:;|")`,
			},
			{
				Description: "StorageAccountKeyInConfig 1",
				FileFilter:  `\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{86}==`,
			},
			{
				Description: "StorageAccountKeyInCode 1",
				FileFilter:  `(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$`,
				Rule:        `[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{86}==`,
			},
			{
				Description: "SharedAccessSignatureInCode 1",
				FileFilter:  `(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$`,
				Rule:        `[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{43}=[^{@]`,
			},
			{
				Description: "SharedAccessSignatureInCode 2",
				FileFilter:  `(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$`,
				Rule:        `[^a-z0-9/\+\._\-\$,\\][a-z0-9%]{43,53}%3d[^a-z0-9%]`,
			},
			{
				Description: "SharedAccessSignatureInConfig 1",
				FileFilter:  `\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{43}=[^{@]`,
			},
			{
				Description: "SharedAccessSignatureInConfig 2",
				FileFilter:  `\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `[^a-z0-9/\+\._\-\$,\\][a-z0-9%]{43,53}%3d[^a-z0-9%]`,
			},
			{
				Description: "GeneralSecretInConfig 1",
				FileFilter:  `\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `<add\skey="[^"]+(?:key(?:s|[0-9])?|credentials?|secret(?:s|[0-9])?|password|token|KeyPrimary|KeySecondary|KeyOrSas|KeyEncrypted)"\s*value\s*="[^"]+"[^>]*/>`,
			},
			{
				Description: "GeneralSecretInConfig 2",
				FileFilter:  `\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `<add\skey="[^"]+"\s*value="[^"]*EncryptedSecret:[^"]+"\s*/>`,
			},
			{
				Description: "GeneralSecretInConfig 3",
				FileFilter:  `\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `<Credential\sname="[^"]*(?:key(?:s|[0-9])?|credentials?|secret(?:s|[0-9])?|password|token|KeyPrimary|KeySecondary|KeyOrSas|KeyEncrypted)"(\s*value\s*="[^"]+".*?/>|[^>]*>.*?</Credential>)`,
			},
			{
				Description: "GeneralSecretInConfig 4",
				FileFilter:  `\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot`,
				Rule:        `<setting\sname="[^"]*Password".*[\r?\n]*\s*<value>.+</value>`,
			},
			{
				Description: "ScriptPassword 1",
				FileFilter:  `(?:\.cmd|\.ps|\.ps1|\.psm1)$`,
				Rule:        `\s-Password\s+(?:"[^"]*"|'[^']*')`,
			},
			{
				Description: "ScriptPassword 2",
				FileFilter:  `(?:\.cmd|\.ps|\.ps1|\.psm1)$`,
				Rule:        `\s-Password\s+[^$\(\)\[\{<\-\r?\n]+\s*(?:\r?\n|\-)`,
			},
			{
				Description: "ExternalApiSecret",
				FileFilter:  `\.cs$|\.cpp$|\.c$`,
				Rule:        `(private\sconst\sstring\sAccessTokenSecret|private\sconst\sstring\saccessToken|private\sconst\sstring\sconsumerSecret|private\sconst\sstring\sconsumerKey|pageAccessToken|private\sstring\stwilioAccountSid|private\sstring\stwilioAuthToken)\s=\s".*";`,
			},
			{
				Description: "DefaultPasswordContexts 1",
				FileFilter:  `\.(?:ps1|psm1|)$`,
				Rule:        `ConvertTo-SecureString(?:\s*-String)?\s*"[^"\r?\n]+"`,
			},
			{
				Description: "DefaultPasswordContexts 2",
				FileFilter:  `\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$`,
				Rule:        `new\sX509Certificate2\([^()]*,\s*"[^"\r?\n]+"[^)]*\)`,
			},
			{
				Description: "DefaultPasswordContexts 3",
				FileFilter:  `\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$`,
				Rule:        `AdminPassword\s*=\s*"[^"\r?\n]+"`,
			},
			{
				Description: "DefaultPasswordContexts 4",
				FileFilter:  `\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$`,
				Rule:        `(?i)<password>.+</password>`,
			},
			{
				Description: "DefaultPasswordContexts 5",
				FileFilter:  `\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$`,
				Rule:        `ClearTextPassword"?\s*[:=]\s*"[^"\r?\n]+"`,
			},
			{
				Description: "DefaultPasswordContexts 6",
				FileFilter:  `\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$`,
				Rule:        `certutil.*?\-p\s+("[^"%]+"|'[^'%]+'|[^"']\S*\s)`,
			},
			{
				Description: "DefaultPasswordContexts 7",
				FileFilter:  `\.(?:cs|xml|config|json|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$`,
				Rule:        `password\s*=\s*N?(["][^"\r?\n]{4,}["]|['][^'\r?\n]{4,}['])`,
			},
			{
				Description: "DomainPassword",
				Rule:        `new(?:-object)?\s+System.Net.NetworkCredential\(?:.*?,\s*"[^"]+"`,
				FileFilter:  `\.cs$|\.c$|\.cpp$|\.ps1$|\.ps$|\.cmd$|\.bat$|\.log$|\.psd$|\.psm1$`,
			},
			{
				Description: "VstsPersonalAccessToken 1",
				FileFilter:  `\.(?:cs|ps1|bat|config|xml|json)$`,
				Rule:        `(?i)(?:AccessToken|pat|token).*?[':="][a-z0-9]{52}(?:'|"|\s|[\r?\n]+)`,
			},
			{
				Description: "VstsPersonalAccessToken 1",
				FileFilter:  `\.(?:cs|ps1|bat|config|xml|json)$`,
				Rule:        `(?i)(?:AccessToken|pat|token).*?[':="][a-z0-9/+]{70}==(?:'|"|\s|[\r?\n]+)`,
			},
			{
				Description: "OAuthToken 1",
				FileFilter:  `\.(?:config|js|json|txt|cs|xml|java|py)$`,
				Rule:        `eyj[a-z0-9\-_%]+\.eyj[a-z0-9\-_%]+\.[a-z0-9\-_%]+`,
			},
			{
				Description: "OAuthToken 2",
				FileFilter:  `\.(?:config|js|json|txt|cs|xml|java|py)$`,
				Rule:        `refresh_token["']?\s*[:=]\s*["']?(?:[a-z0-9_]+-)+[a-z0-9_]+["']?`,
			},
			{
				Description: "AnsibleVault",
				FileFilter:  `\.yml$`,
				Rule:        `\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256[\r?\n]+[0-9]+`,
			},
			{
				Description: "SlackToken 1",
				Rule:        `xoxp-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+`,
			},
			{
				Description: "SlackToken 2",
				Rule:        `xoxb-[a-z0-9]+-[a-z0-9]+`,
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
