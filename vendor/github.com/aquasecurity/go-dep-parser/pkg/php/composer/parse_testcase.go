package composer

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", },"'
	ComposerNormal = []types.Library{
		{Name: "pear/log", Version: "1.13.1"},
		{Name: "pear/pear_exception", Version: "v1.0.0"},
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", },"'
	ComposerLaravel = []types.Library{
		{Name: "guzzlehttp/guzzle", Version: "6.3.3"},
		{Name: "guzzlehttp/promises", Version: "v1.3.1"},
		{Name: "guzzlehttp/psr7", Version: "1.5.2"},
		{Name: "laravel/installer", Version: "v2.0.1"},
		{Name: "pear/log", Version: "1.13.1"},
		{Name: "pear/pear_exception", Version: "v1.0.0"},
		{Name: "psr/http-message", Version: "1.0.1"},
		{Name: "ralouphie/getallheaders", Version: "2.0.5"},
		{Name: "symfony/console", Version: "v4.2.7"},
		{Name: "symfony/contracts", Version: "v1.0.2"},
		{Name: "symfony/filesystem", Version: "v4.2.7"},
		{Name: "symfony/polyfill-ctype", Version: "v1.11.0"},
		{Name: "symfony/polyfill-mbstring", Version: "v1.11.0"},
		{Name: "symfony/process", Version: "v4.2.7"},
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer require "symfony/symfony"
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", },"'
	ComposerSymfony = []types.Library{
		{Name: "doctrine/annotations", Version: "v1.6.1"},
		{Name: "doctrine/cache", Version: "v1.8.0"},
		{Name: "doctrine/collections", Version: "v1.6.1"},
		{Name: "doctrine/event-manager", Version: "v1.0.0"},
		{Name: "doctrine/lexer", Version: "v1.0.1"},
		{Name: "doctrine/persistence", Version: "1.1.1"},
		{Name: "doctrine/reflection", Version: "v1.0.0"},
		{Name: "fig/link-util", Version: "1.0.0"},
		{Name: "guzzlehttp/guzzle", Version: "6.3.3"},
		{Name: "guzzlehttp/promises", Version: "v1.3.1"},
		{Name: "guzzlehttp/psr7", Version: "1.5.2"},
		{Name: "laravel/installer", Version: "v2.0.1"},
		{Name: "pear/log", Version: "1.13.1"},
		{Name: "pear/pear_exception", Version: "v1.0.0"},
		{Name: "psr/cache", Version: "1.0.1"},
		{Name: "psr/container", Version: "1.0.0"},
		{Name: "psr/http-message", Version: "1.0.1"},
		{Name: "psr/link", Version: "1.0.0"},
		{Name: "psr/log", Version: "1.1.0"},
		{Name: "psr/simple-cache", Version: "1.0.1"},
		{Name: "ralouphie/getallheaders", Version: "2.0.5"},
		{Name: "symfony/contracts", Version: "v1.0.2"},
		{Name: "symfony/polyfill-ctype", Version: "v1.11.0"},
		{Name: "symfony/polyfill-intl-icu", Version: "v1.11.0"},
		{Name: "symfony/polyfill-mbstring", Version: "v1.11.0"},
		{Name: "symfony/polyfill-php72", Version: "v1.11.0"},
		{Name: "symfony/symfony", Version: "v4.2.7"},
		{Name: "twig/twig", Version: "v2.9.0"},
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer require "symfony/symfony"
	// composer require fzaninotto/faker --dev
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", },"'
	ComposerWithDev = []types.Library{
		{Name: "doctrine/annotations", Version: "v1.6.1"},
		{Name: "doctrine/cache", Version: "v1.8.0"},
		{Name: "doctrine/collections", Version: "v1.6.1"},
		{Name: "doctrine/event-manager", Version: "v1.0.0"},
		{Name: "doctrine/lexer", Version: "v1.0.1"},
		{Name: "doctrine/persistence", Version: "1.1.1"},
		{Name: "doctrine/reflection", Version: "v1.0.0"},
		{Name: "fig/link-util", Version: "1.0.0"},
		{Name: "guzzlehttp/guzzle", Version: "6.3.3"},
		{Name: "guzzlehttp/promises", Version: "v1.3.1"},
		{Name: "guzzlehttp/psr7", Version: "1.5.2"},
		{Name: "laravel/installer", Version: "v2.0.1"},
		{Name: "pear/log", Version: "1.13.1"},
		{Name: "pear/pear_exception", Version: "v1.0.0"},
		{Name: "psr/cache", Version: "1.0.1"},
		{Name: "psr/container", Version: "1.0.0"},
		{Name: "psr/http-message", Version: "1.0.1"},
		{Name: "psr/link", Version: "1.0.0"},
		{Name: "psr/log", Version: "1.1.0"},
		{Name: "psr/simple-cache", Version: "1.0.1"},
		{Name: "ralouphie/getallheaders", Version: "2.0.5"},
		{Name: "symfony/contracts", Version: "v1.0.2"},
		{Name: "symfony/polyfill-ctype", Version: "v1.11.0"},
		{Name: "symfony/polyfill-intl-icu", Version: "v1.11.0"},
		{Name: "symfony/polyfill-mbstring", Version: "v1.11.0"},
		{Name: "symfony/polyfill-php72", Version: "v1.11.0"},
		{Name: "symfony/symfony", Version: "v4.2.7"},
		{Name: "twig/twig", Version: "v2.9.0"},
	}
)
