package composer

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerNormal = []types.Library{
		{"pear/log", "1.13.1", ""},
		{"pear/pear_exception", "v1.0.0", ""},
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerLaravel = []types.Library{
		{"guzzlehttp/guzzle", "6.3.3", ""},
		{"guzzlehttp/promises", "v1.3.1", ""},
		{"guzzlehttp/psr7", "1.5.2", ""},
		{"laravel/installer", "v2.0.1", ""},
		{"pear/log", "1.13.1", ""},
		{"pear/pear_exception", "v1.0.0", ""},
		{"psr/http-message", "1.0.1", ""},
		{"ralouphie/getallheaders", "2.0.5", ""},
		{"symfony/console", "v4.2.7", ""},
		{"symfony/contracts", "v1.0.2", ""},
		{"symfony/filesystem", "v4.2.7", ""},
		{"symfony/polyfill-ctype", "v1.11.0", ""},
		{"symfony/polyfill-mbstring", "v1.11.0", ""},
		{"symfony/process", "v4.2.7", ""},
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer require "symfony/symfony"
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerSymfony = []types.Library{
		{"doctrine/annotations", "v1.6.1", ""},
		{"doctrine/cache", "v1.8.0", ""},
		{"doctrine/collections", "v1.6.1", ""},
		{"doctrine/event-manager", "v1.0.0", ""},
		{"doctrine/lexer", "v1.0.1", ""},
		{"doctrine/persistence", "1.1.1", ""},
		{"doctrine/reflection", "v1.0.0", ""},
		{"fig/link-util", "1.0.0", ""},
		{"guzzlehttp/guzzle", "6.3.3", ""},
		{"guzzlehttp/promises", "v1.3.1", ""},
		{"guzzlehttp/psr7", "1.5.2", ""},
		{"laravel/installer", "v2.0.1", ""},
		{"pear/log", "1.13.1", ""},
		{"pear/pear_exception", "v1.0.0", ""},
		{"psr/cache", "1.0.1", ""},
		{"psr/container", "1.0.0", ""},
		{"psr/http-message", "1.0.1", ""},
		{"psr/link", "1.0.0", ""},
		{"psr/log", "1.1.0", ""},
		{"psr/simple-cache", "1.0.1", ""},
		{"ralouphie/getallheaders", "2.0.5", ""},
		{"symfony/contracts", "v1.0.2", ""},
		{"symfony/polyfill-ctype", "v1.11.0", ""},
		{"symfony/polyfill-intl-icu", "v1.11.0", ""},
		{"symfony/polyfill-mbstring", "v1.11.0", ""},
		{"symfony/polyfill-php72", "v1.11.0", ""},
		{"symfony/symfony", "v4.2.7", ""},
		{"twig/twig", "v2.9.0", ""},
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer require "symfony/symfony"
	// composer require fzaninotto/faker --dev
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerWithDev = []types.Library{
		{"doctrine/annotations", "v1.6.1", ""},
		{"doctrine/cache", "v1.8.0", ""},
		{"doctrine/collections", "v1.6.1", ""},
		{"doctrine/event-manager", "v1.0.0", ""},
		{"doctrine/lexer", "v1.0.1", ""},
		{"doctrine/persistence", "1.1.1", ""},
		{"doctrine/reflection", "v1.0.0", ""},
		{"fig/link-util", "1.0.0", ""},
		{"guzzlehttp/guzzle", "6.3.3", ""},
		{"guzzlehttp/promises", "v1.3.1", ""},
		{"guzzlehttp/psr7", "1.5.2", ""},
		{"laravel/installer", "v2.0.1", ""},
		{"pear/log", "1.13.1", ""},
		{"pear/pear_exception", "v1.0.0", ""},
		{"psr/cache", "1.0.1", ""},
		{"psr/container", "1.0.0", ""},
		{"psr/http-message", "1.0.1", ""},
		{"psr/link", "1.0.0", ""},
		{"psr/log", "1.1.0", ""},
		{"psr/simple-cache", "1.0.1", ""},
		{"ralouphie/getallheaders", "2.0.5", ""},
		{"symfony/contracts", "v1.0.2", ""},
		{"symfony/polyfill-ctype", "v1.11.0", ""},
		{"symfony/polyfill-intl-icu", "v1.11.0", ""},
		{"symfony/polyfill-mbstring", "v1.11.0", ""},
		{"symfony/polyfill-php72", "v1.11.0", ""},
		{"symfony/symfony", "v4.2.7", ""},
		{"twig/twig", "v2.9.0", ""},
	}
)
