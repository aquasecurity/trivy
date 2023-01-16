package apk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	oldAlpineConfig = &v1.ConfigFile{
		Architecture: "amd64",
		Container:    "f5b08762ace1af069127a337579acd51c415b919d736e6615b453a3c6fbf260d",
		Created: v1.Time{
			Time: time.Date(2018, time.October, 15, 21, 28, 53, 798628678, time.UTC),
		},
		DockerVersion: "17.06.2-ce",
		History: []v1.History{
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 11, 22, 19, 38, 885299940, time.UTC),
				},
				CreatedBy: "/bin/sh -c #(nop) ADD file:49f9e47e678d868d5b023482aa8dded71276a241a665c4f8b55ca77269321b34 in / ",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 11, 22, 19, 39, 58628442, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 26, 59, 951316015, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 1, 470388635, time.UTC),
				},
				CreatedBy: "/bin/sh -c apk add --no-cache --virtual .persistent-deps \t\tca-certificates \t\tcurl \t\ttar \t\txz \t\tlibressl",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 2, 432381785, time.UTC),
				},
				CreatedBy: "/bin/sh -c set -x \t&& addgroup -g 82 -S www-data \t&& adduser -u 82 -D -S -G www-data www-data",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 2, 715120309, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_INI_DIR=/usr/local/etc/php",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 3, 655421341, time.UTC),
				},
				CreatedBy: "/bin/sh -c mkdir -p $PHP_INI_DIR/conf.d",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 3, 931799562, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 4, 210945499, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 4, 523116501, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.September, 12, 1, 27, 4, 795176159, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 2, 18, 415761689, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_VERSION=7.2.11",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 2, 18, 599097853, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_URL=https://secure.php.net/get/php-7.2.11.tar.xz/from/this/mirror PHP_ASC_URL=https://secure.php.net/get/php-7.2.11.tar.xz.asc/from/this/mirror",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 2, 18, 782890412, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_SHA256=da1a705c0bc46410e330fc6baa967666c8cd2985378fb9707c01a8e33b01d985 PHP_MD5=",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 2, 22, 795846753, time.UTC),
				},
				CreatedBy: "/bin/sh -c set -xe; \t\tapk add --no-cache --virtual .fetch-deps \t\tgnupg \t\twget \t; \t\tmkdir -p /usr/src; \tcd /usr/src; \t\twget -O php.tar.xz \"$PHP_URL\"; \t\tif [ -n \"$PHP_SHA256\" ]; then \t\techo \"$PHP_SHA256 *php.tar.xz\" | sha256sum -c -; \tfi; \tif [ -n \"$PHP_MD5\" ]; then \t\techo \"$PHP_MD5 *php.tar.xz\" | md5sum -c -; \tfi; \t\tif [ -n \"$PHP_ASC_URL\" ]; then \t\twget -O php.tar.xz.asc \"$PHP_ASC_URL\"; \t\texport GNUPGHOME=\"$(mktemp -d)\"; \t\tfor key in $GPG_KEYS; do \t\t\tgpg --keyserver ha.pool.sks-keyservers.net --recv-keys \"$key\"; \t\tdone; \t\tgpg --batch --verify php.tar.xz.asc php.tar.xz; \t\tcommand -v gpgconf > /dev/null && gpgconf --kill all; \t\trm -rf \"$GNUPGHOME\"; \tfi; \t\tapk del .fetch-deps",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 2, 23, 71406376, time.UTC),
				},
				CreatedBy: "/bin/sh -c #(nop) COPY file:207c686e3fed4f71f8a7b245d8dcae9c9048d276a326d82b553c12a90af0c0ca in /usr/local/bin/ ",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 7, 13, 93396680, time.UTC),
				},
				CreatedBy: "/bin/sh -c set -xe \t&& apk add --no-cache --virtual .build-deps \t\t$PHPIZE_DEPS \t\tcoreutils \t\tcurl-dev \t\tlibedit-dev \t\tlibressl-dev \t\tlibsodium-dev \t\tlibxml2-dev \t\tsqlite-dev \t\t&& export CFLAGS=\"$PHP_CFLAGS\" \t\tCPPFLAGS=\"$PHP_CPPFLAGS\" \t\tLDFLAGS=\"$PHP_LDFLAGS\" \t&& docker-php-source extract \t&& cd /usr/src/php \t&& gnuArch=\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\" \t&& ./configure \t\t--build=\"$gnuArch\" \t\t--with-config-file-path=\"$PHP_INI_DIR\" \t\t--with-config-file-scan-dir=\"$PHP_INI_DIR/conf.d\" \t\t\t\t--enable-option-checking=fatal \t\t\t\t--with-mhash \t\t\t\t--enable-ftp \t\t--enable-mbstring \t\t--enable-mysqlnd \t\t--with-sodium=shared \t\t\t\t--with-curl \t\t--with-libedit \t\t--with-openssl \t\t--with-zlib \t\t\t\t$(test \"$gnuArch\" = 's390x-linux-gnu' && echo '--without-pcre-jit') \t\t\t\t$PHP_EXTRA_CONFIGURE_ARGS \t&& make -j \"$(nproc)\" \t&& make install \t&& { find /usr/local/bin /usr/local/sbin -type f -perm +0111 -exec strip --strip-all '{}' + || true; } \t&& make clean \t\t&& cp -v php.ini-* \"$PHP_INI_DIR/\" \t\t&& cd / \t&& docker-php-source delete \t\t&& runDeps=\"$( \t\tscanelf --needed --nobanner --format '%n#p' --recursive /usr/local \t\t\t| tr ',' '\\n' \t\t\t| sort -u \t\t\t| awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }' \t)\" \t&& apk add --no-cache --virtual .php-rundeps $runDeps \t\t&& apk del .build-deps \t\t&& pecl update-channels \t&& rm -rf /tmp/pear ~/.pearrc",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 7, 13, 722586262, time.UTC),
				},
				CreatedBy: "/bin/sh -c #(nop) COPY multi:2cdcedabcf5a3b9ae610fab7848e94bc2f64b4d85710d55fd6f79e44dacf73d8 in /usr/local/bin/ ",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 7, 14, 618087104, time.UTC),
				},
				CreatedBy: "/bin/sh -c docker-php-ext-enable sodium",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 7, 14, 826981756, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENTRYPOINT [\"docker-php-entrypoint\"]",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 19, 7, 15, 10831572, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  CMD [\"php\" \"-a\"]",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 21, 919735971, time.UTC),
				},
				CreatedBy: "/bin/sh -c apk --no-cache add git subversion openssh mercurial tini bash patch",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 22, 611763893, time.UTC),
				},
				CreatedBy: "/bin/sh -c echo \"memory_limit=-1\" > \"$PHP_INI_DIR/conf.d/memory-limit.ini\"  && echo \"date.timezone=${PHP_TIMEZONE:-UTC}\" > \"$PHP_INI_DIR/conf.d/date_timezone.ini\"",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 50, 224278478, time.UTC),
				},
				CreatedBy: "/bin/sh -c apk add --no-cache --virtual .build-deps zlib-dev  && docker-php-ext-install zip  && runDeps=\"$(     scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions     | tr ',' '\\n'     | sort -u     | awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }'     )\"  && apk add --virtual .composer-phpext-rundeps $runDeps  && apk del .build-deps",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 50, 503010161, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_ALLOW_SUPERUSER=1",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 50, 775378559, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_HOME=/tmp",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					time.Date(2018, time.October, 15, 21, 28, 51, 35012363, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_VERSION=1.7.2",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 52, 491402624, time.UTC),
				},
				CreatedBy: "/bin/sh -c curl --silent --fail --location --retry 3 --output /tmp/installer.php --url https://raw.githubusercontent.com/composer/getcomposer.org/b107d959a5924af895807021fcef4ffec5a76aa9/web/installer  && php -r \"     \\$signature = '544e09ee996cdf60ece3804abc52599c22b1f40f4323403c44d44fdfdd586475ca9813a858088ffbc1f233e9b180f061';     \\$hash = hash('SHA384', file_get_contents('/tmp/installer.php'));     if (!hash_equals(\\$signature, \\$hash)) {         unlink('/tmp/installer.php');         echo 'Integrity check failed, installer is either corrupt or worse.' . PHP_EOL;         exit(1);     }\"  && php /tmp/installer.php --no-ansi --install-dir=/usr/bin --filename=composer --version=${COMPOSER_VERSION}  && composer --ansi --version --no-interaction  && rm -rf /tmp/* /tmp/.htaccess",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 52, 948859545, time.UTC),
				},
				CreatedBy: "/bin/sh -c #(nop) COPY file:295943a303e8f27de4302b6aa3687bce4b1d1392335efaaab9ecd37bec5ab4c5 in /docker-entrypoint.sh ",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 53, 295399872, time.UTC),
				},
				CreatedBy: "/bin/sh -c #(nop) WORKDIR /app",
			},
			{
				Created: v1.Time{
					Time: time.Date(2018, time.October, 15, 21, 28, 53, 582920705, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  ENTRYPOINT [\"/bin/sh\" \"/docker-entrypoint.sh\"]",
				EmptyLayer: true,
			},
			{
				Created: v1.Time{
					time.Date(2018, time.October, 15, 21, 28, 53, 798628678, time.UTC),
				},
				CreatedBy:  "/bin/sh -c #(nop)  CMD [\"composer\"]",
				EmptyLayer: true,
			},
		},
		OS: "linux",
		RootFS: v1.RootFS{
			Type: "layers",
			DiffIDs: []v1.Hash{
				{
					Algorithm: "sha256",
					Hex:       "ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
				},
				{
					Algorithm: "sha256",
					Hex:       "0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
				},
				{
					Algorithm: "sha256",
					Hex:       "9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
				},
				{
					Algorithm: "sha256",
					Hex:       "dc00fbef458ad3204bbb548e2d766813f593d857b845a940a0de76aed94c94d1",
				},
				{
					Algorithm: "sha256",
					Hex:       "5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
				},
				{
					Algorithm: "sha256",
					Hex:       "9bdb2c849099a99c8ab35f6fd7469c623635e8f4479a0a5a3df61e22bae509f6",
				},
				{
					Algorithm: "sha256",
					Hex:       "6408527580eade39c2692dbb6b0f6a9321448d06ea1c2eef06bb7f37da9c5013",
				},
				{
					Algorithm: "sha256",
					Hex:       "83abef706f5ae199af65d1c13d737d0eb36219f0d18e36c6d8ff06159df39a63",
				},
				{
					Algorithm: "sha256",
					Hex:       "c03283c257abd289a30b4f5e9e1345da0e9bfdc6ca398ee7e8fac6d2c1456227",
				},
				{
					Algorithm: "sha256",
					Hex:       "2da3602d664dd3f71fae83cbc566d4e80b432c6ee8bb4efd94c8e85122f503d4",
				},
				{
					Algorithm: "sha256",
					Hex:       "82c59ac8ee582542648e634ca5aff9a464c68ff8a054f105a58689fb52209e34",
				},
				{
					Algorithm: "sha256",
					Hex:       "2f4a5c9187c249834ebc28783bd3c65bdcbacaa8baa6620ddaa27846dd3ef708",
				},
				{
					Algorithm: "sha256",
					Hex:       "6ca56f561e677ae06c3bc87a70792642d671a4416becb9a101577c1a6e090e36",
				},
				{
					Algorithm: "sha256",
					Hex:       "154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
				},
				{
					Algorithm: "sha256",
					Hex:       "b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
				},
			},
		},
		Config: v1.Config{
			Cmd: []string{"composer"},
			Entrypoint: []string{
				"/bin/sh",
				"/docker-entrypoint.sh",
			},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
				"PHP_INI_DIR=/usr/local/etc/php",
				"PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				"PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				"PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie",
				"GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F",
				"PHP_VERSION=7.2.11",
				"PHP_URL=https://secure.php.net/get/php-7.2.11.tar.xz/from/this/mirror",
				"PHP_ASC_URL=https://secure.php.net/get/php-7.2.11.tar.xz.asc/from/this/mirror",
				"PHP_SHA256=da1a705c0bc46410e330fc6baa967666c8cd2985378fb9707c01a8e33b01d985",
				"PHP_MD5=",
				"COMPOSER_ALLOW_SUPERUSER=1",
				"COMPOSER_HOME=/tmp",
				"COMPOSER_VERSION=1.7.2",
			},
			Image:       "sha256:ad8c55ed62ca1f439bd600c7251de347926ca901ab7f52a93d8fba743ef397c6",
			WorkingDir:  "/app",
			ArgsEscaped: true,
		},
	}

	alpineConfig = &v1.ConfigFile{
		Architecture:  "amd64",
		Container:     "47d9d33b3d5abb0316dba1a0bfcbc12a6fa88d98ad30170c41d30718003de82e",
		Created:       v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 20, 331457195, time.UTC)},
		DockerVersion: "18.06.1-ce",
		History: []v1.History{
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 0, 7, 3, 358250803, time.UTC)},
				CreatedBy: "/bin/sh -c #(nop) ADD file:a86aea1f3a7d68f6ae03397b99ea77f2e9ee901c5c59e59f76f93adbb4035913 in / ",
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 0, 7, 3, 510395965, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 43, 80069360, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
				EmptyLayer: true,
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 44, 655269947, time.UTC)},
				CreatedBy: "/bin/sh -c apk add --no-cache \t\tca-certificates \t\tcurl \t\ttar \t\txz \t\topenssl",
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 45, 787769041, time.UTC)},
				CreatedBy: "/bin/sh -c set -x \t&& addgroup -g 82 -S www-data \t&& adduser -u 82 -D -S -G www-data www-data",
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 46, 47800659, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_INI_DIR=/usr/local/etc/php",
				EmptyLayer: true,
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 47, 131691293, time.UTC)},
				CreatedBy: "/bin/sh -c set -eux; \tmkdir -p \"$PHP_INI_DIR/conf.d\"; \t[ ! -d /var/www/html ]; \tmkdir -p /var/www/html; \tchown www-data:www-data /var/www/html; \tchmod 777 /var/www/html",
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 47, 360137598, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 47, 624002469, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 47, 823552655, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 48, 90975339, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV GPG_KEYS=CBAF69F173A0FEA4B537F470D66C9593118BCCB6 F38252826ACD957EF380D39F2F7956BC5DA04B5D",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 48, 311134986, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_VERSION=7.3.5",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 48, 546724822, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_URL=https://www.php.net/get/php-7.3.5.tar.xz/from/this/mirror PHP_ASC_URL=https://www.php.net/get/php-7.3.5.tar.xz.asc/from/this/mirror",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 48, 787069773, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_SHA256=e1011838a46fd4a195c8453b333916622d7ff5bce4aca2d9d99afac142db2472 PHP_MD5=",
				EmptyLayer: true,
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 54, 588915046, time.UTC)},
				CreatedBy: "/bin/sh -c set -xe; \t\tapk add --no-cache --virtual .fetch-deps \t\tgnupg \t\twget \t; \t\tmkdir -p /usr/src; \tcd /usr/src; \t\twget -O php.tar.xz \"$PHP_URL\"; \t\tif [ -n \"$PHP_SHA256\" ]; then \t\techo \"$PHP_SHA256 *php.tar.xz\" | sha256sum -c -; \tfi; \tif [ -n \"$PHP_MD5\" ]; then \t\techo \"$PHP_MD5 *php.tar.xz\" | md5sum -c -; \tfi; \t\tif [ -n \"$PHP_ASC_URL\" ]; then \t\twget -O php.tar.xz.asc \"$PHP_ASC_URL\"; \t\texport GNUPGHOME=\"$(mktemp -d)\"; \t\tfor key in $GPG_KEYS; do \t\t\tgpg --batch --keyserver ha.pool.sks-keyservers.net --recv-keys \"$key\"; \t\tdone; \t\tgpg --batch --verify php.tar.xz.asc php.tar.xz; \t\tcommand -v gpgconf > /dev/null && gpgconf --kill all; \t\trm -rf \"$GNUPGHOME\"; \tfi; \t\tapk del --no-network .fetch-deps",
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 4, 54, 868883630, time.UTC)},
				CreatedBy: "/bin/sh -c #(nop) COPY file:ce57c04b70896f77cc11eb2766417d8a1240fcffe5bba92179ec78c458844110 in /usr/local/bin/ ",
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 12, 28, 585346378, time.UTC)},
				CreatedBy: "/bin/sh -c set -xe \t&& apk add --no-cache --virtual .build-deps \t\t$PHPIZE_DEPS \t\targon2-dev \t\tcoreutils \t\tcurl-dev \t\tlibedit-dev \t\tlibsodium-dev \t\tlibxml2-dev \t\topenssl-dev \t\tsqlite-dev \t\t&& export CFLAGS=\"$PHP_CFLAGS\" \t\tCPPFLAGS=\"$PHP_CPPFLAGS\" \t\tLDFLAGS=\"$PHP_LDFLAGS\" \t&& docker-php-source extract \t&& cd /usr/src/php \t&& gnuArch=\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\" \t&& ./configure \t\t--build=\"$gnuArch\" \t\t--with-config-file-path=\"$PHP_INI_DIR\" \t\t--with-config-file-scan-dir=\"$PHP_INI_DIR/conf.d\" \t\t\t\t--enable-option-checking=fatal \t\t\t\t--with-mhash \t\t\t\t--enable-ftp \t\t--enable-mbstring \t\t--enable-mysqlnd \t\t--with-password-argon2 \t\t--with-sodium=shared \t\t\t\t--with-curl \t\t--with-libedit \t\t--with-openssl \t\t--with-zlib \t\t\t\t$(test \"$gnuArch\" = 's390x-linux-gnu' && echo '--without-pcre-jit') \t\t\t\t$PHP_EXTRA_CONFIGURE_ARGS \t&& make -j \"$(nproc)\" \t&& find -type f -name '*.a' -delete \t&& make install \t&& { find /usr/local/bin /usr/local/sbin -type f -perm +0111 -exec strip --strip-all '{}' + || true; } \t&& make clean \t\t&& cp -v php.ini-* \"$PHP_INI_DIR/\" \t\t&& cd / \t&& docker-php-source delete \t\t&& runDeps=\"$( \t\tscanelf --needed --nobanner --format '%n#p' --recursive /usr/local \t\t\t| tr ',' '\\n' \t\t\t| sort -u \t\t\t| awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }' \t)\" \t&& apk add --no-cache $runDeps \t\t&& apk del --no-network .build-deps \t\t&& pecl update-channels \t&& rm -rf /tmp/pear ~/.pearrc",
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 12, 29, 98563791, time.UTC)},
				CreatedBy: "/bin/sh -c #(nop) COPY multi:03970f7b3773444b9f7f244f89d3ceeb4253ac6599f0ba0a4c0306c5bf7d1b9b in /usr/local/bin/ ",
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 3, 12, 30, 99974579, time.UTC)},
				CreatedBy: "/bin/sh -c docker-php-ext-enable sodium",
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 12, 30, 266754534, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENTRYPOINT [\"docker-php-entrypoint\"]",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 3, 12, 30, 414982715, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  CMD [\"php\" \"-a\"]",
				EmptyLayer: true,
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 12, 574223281, time.UTC)},
				CreatedBy: "/bin/sh -c apk add --no-cache --virtual .composer-rundeps git subversion openssh mercurial tini bash patch make zip unzip coreutils  && apk add --no-cache --virtual .build-deps zlib-dev libzip-dev  && docker-php-ext-configure zip --with-libzip  && docker-php-ext-install -j$(getconf _NPROCESSORS_ONLN) zip opcache  && runDeps=\"$(     scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions       | tr ',' '\\n'       | sort -u       | awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }'     )\"  && apk add --no-cache --virtual .composer-phpext-rundeps $runDeps  && apk del .build-deps  && printf \"# composer php cli ini settings\\ndate.timezone=UTC\\nmemory_limit=-1\\nopcache.enable_cli=1\\n\" > $PHP_INI_DIR/php-cli.ini",
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 12, 831274473, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_ALLOW_SUPERUSER=1",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 13, 3330711, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_HOME=/tmp",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 18, 503381656, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_VERSION=1.7.3",
				EmptyLayer: true,
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 19, 619504049, time.UTC)},
				CreatedBy: "/bin/sh -c curl --silent --fail --location --retry 3 --output /tmp/installer.php --url https://raw.githubusercontent.com/composer/getcomposer.org/cb19f2aa3aeaa2006c0cd69a7ef011eb31463067/web/installer  && php -r \"     \\$signature = '48e3236262b34d30969dca3c37281b3b4bbe3221bda826ac6a9a62d6444cdb0dcd0615698a5cbe587c3f0fe57a54d8f5';     \\$hash = hash('sha384', file_get_contents('/tmp/installer.php'));     if (!hash_equals(\\$signature, \\$hash)) {       unlink('/tmp/installer.php');       echo 'Integrity check failed, installer is either corrupt or worse.' . PHP_EOL;       exit(1);     }\"  && php /tmp/installer.php --no-ansi --install-dir=/usr/bin --filename=composer --version=${COMPOSER_VERSION}  && composer --ansi --version --no-interaction  && rm -f /tmp/installer.php",
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 19, 803213107, time.UTC)},
				CreatedBy: "/bin/sh -c #(nop) COPY file:0bcb2d1c76549e38469db832f5bcfcb4c538b26748a9d4246cc64f35a23280d0 in /docker-entrypoint.sh ",
			},
			{
				Created:   v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 19, 987396089, time.UTC)},
				CreatedBy: "/bin/sh -c #(nop) WORKDIR /app",
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 20, 159217819, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  ENTRYPOINT [\"/bin/sh\" \"/docker-entrypoint.sh\"]",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: time.Date(2019, time.May, 11, 5, 10, 20, 331457195, time.UTC)},
				CreatedBy:  "/bin/sh -c #(nop)  CMD [\"composer\"]",
				EmptyLayer: true,
			},
		},
		OS: "linux",
		RootFS: v1.RootFS{
			Type: "layers",
			DiffIDs: []v1.Hash{
				{
					Algorithm: "sha256",
					Hex:       "f1b5933fe4b5f49bbe8258745cf396afe07e625bdab3168e364daf7c956b6b81",
				},
				{
					Algorithm: "sha256",
					Hex:       "3575e617b5f4845d72ac357ea1712be9037c1f73e8893fa4a5b887be964f8f59",
				},
				{
					Algorithm: "sha256",
					Hex:       "414e112bbb2c35bef0e76708e87a68b521a011a1941fe6d062e30da800c69d1f",
				},
				{
					Algorithm: "sha256",
					Hex:       "21f626200b4c7decb2150402d3b801a886ef9dab022d11478eb3240b2a1bb175",
				},
				{
					Algorithm: "sha256",
					Hex:       "64a9089492da43bf6f8f3b3b45aafee7d71f1dfd6464477e27b43b4dbe1da341",
				},
				{
					Algorithm: "sha256",
					Hex:       "c60e74b6df1608ee7a080978a9f5eddce48dd4d7366b65a5ec00c6e96deabfae",
				},
				{
					Algorithm: "sha256",
					Hex:       "489ab25ac6f9d77b5868493bfccc72bcbfaa85d8f393cdd21f3a6cb6e0256c15",
				},
				{
					Algorithm: "sha256",
					Hex:       "5a8c7d3402d369f0f5838b74da5c2bd3eaa64c6bbd8d8e11d7ec0affb074c276",
				},
				{
					Algorithm: "sha256",
					Hex:       "fe6bde799f85946dbed35f5f614532d68a9f8b62f3f42ae9164740c3d0a6296a",
				},
				{
					Algorithm: "sha256",
					Hex:       "40dd29f574f814717669b34efc4ae527a3af0829a2cccb9ec4f077a8cb2766cc",
				},
				{
					Algorithm: "sha256",
					Hex:       "0d5d3c0e6691d3c6d24dc782de33d64d490226c503414da0df93b8f605f93da5",
				},
				{
					Algorithm: "sha256",
					Hex:       "41467c77644ee108b8ef3e89db7f235ebb720ed4a4041bf746d7342193e6bc7d",
				},
				{
					Algorithm: "sha256",
					Hex:       "6a64ec219cdeecfe63aac5b7f43fb3cb6651c6b1a02ebbde6deeabf8a7e3b345",
				},
			},
		},
		Config: v1.Config{
			Cmd: []string{"composer"},
			Entrypoint: []string{
				"/bin/sh",
				"/docker-entrypoint.sh",
			},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
				"PHP_INI_DIR=/usr/local/etc/php",
				"PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				"PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2",
				"PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie",
				"GPG_KEYS=CBAF69F173A0FEA4B537F470D66C9593118BCCB6 F38252826ACD957EF380D39F2F7956BC5DA04B5D",
				"PHP_VERSION=7.3.5",
				"PHP_URL=https://www.php.net/get/php-7.3.5.tar.xz/from/this/mirror",
				"PHP_ASC_URL=https://www.php.net/get/php-7.3.5.tar.xz.asc/from/this/mirror",
				"PHP_SHA256=e1011838a46fd4a195c8453b333916622d7ff5bce4aca2d9d99afac142db2472",
				"PHP_MD5=",
				"COMPOSER_ALLOW_SUPERUSER=1",
				"COMPOSER_HOME=/tmp",
				"COMPOSER_VERSION=1.7.3",
			},
			Image:       "sha256:45a1f30c00e614b0d90bb2a24affba0a304ff27660ad4717987fefe067cadec8",
			WorkingDir:  "/app",
			ArgsEscaped: true,
		},
	}

	wantPkgs = &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: "pkgs-from-history",
				Packages: []types.Package{
					{
						Name:    "acl",
						Version: "2.2.52-r5",
					},
					{
						Name:    "apr",
						Version: "1.6.5-r0",
					},
					{
						Name:    "apr-util",
						Version: "1.6.1-r5",
					},
					{
						Name:    "argon2",
						Version: "20171227-r1",
					},
					{
						Name:    "argon2-dev",
						Version: "20171227-r1",
					},
					{
						Name:    "argon2-libs",
						Version: "20171227-r1",
					},
					{
						Name:    "attr",
						Version: "2.4.47-r7",
					},
					{
						Name:    "autoconf",
						Version: "2.69-r2",
					},
					{
						Name:    "bash",
						Version: "4.4.19-r1",
					},
					{
						Name:    "binutils",
						Version: "2.31.1-r2",
					},
					{
						Name:    "busybox",
						Version: "1.29.3-r10",
					},
					{
						Name:    "bzip2",
						Version: "1.0.6-r6",
					},
					{
						Name:    "ca-certificates",
						Version: "20190108-r0",
					},
					{
						Name:    "coreutils",
						Version: "8.30-r0",
					},
					{
						Name:    "curl",
						Version: "7.64.0-r1",
					},
					{
						Name:    "curl-dev",
						Version: "7.64.0-r1",
					},
					{
						Name:    "cyrus-sasl",
						Version: "2.1.27-r1",
					},
					{
						Name:    "db",
						Version: "5.3.28-r1",
					},
					{
						Name:    "dpkg",
						Version: "1.19.2-r0",
					},
					{
						Name:    "dpkg-dev",
						Version: "1.19.2-r0",
					},
					{
						Name:    "expat",
						Version: "2.2.6-r0",
					},
					{
						Name:    "file",
						Version: "5.36-r0",
					},
					{
						Name:    "g++",
						Version: "8.3.0-r0",
					},
					{
						Name:    "gcc",
						Version: "8.3.0-r0",
					},
					{
						Name:    "gdbm",
						Version: "1.13-r1",
					},
					{
						Name:    "git",
						Version: "2.20.1-r0",
					},
					{
						Name:    "gmp",
						Version: "6.1.2-r1",
					},
					{
						Name:    "gnupg",
						Version: "2.2.12-r0",
					},
					{
						Name:    "gnutls",
						Version: "3.6.7-r0",
					},
					{
						Name:    "isl",
						Version: "0.18-r0",
					},
					{
						Name:    "libacl",
						Version: "2.2.52-r5",
					},
					{
						Name:    "libassuan",
						Version: "2.5.1-r0",
					},
					{
						Name:    "libatomic",
						Version: "8.3.0-r0",
					},
					{
						Name:    "libattr",
						Version: "2.4.47-r7",
					},
					{
						Name:    "libbz2",
						Version: "1.0.6-r6",
					},
					{
						Name:    "libc-dev",
						Version: "0.7.1-r0",
					},
					{
						Name:    "libcap",
						Version: "2.26-r0",
					},
					{
						Name:    "libcrypto1.1",
						Version: "1.1.1b-r1",
					},
					{
						Name:    "libcurl",
						Version: "7.64.0-r1",
					},
					{
						Name:    "libedit",
						Version: "20181209.3.1-r0",
					},
					{
						Name:    "libedit-dev",
						Version: "20181209.3.1-r0",
					},
					{
						Name:    "libffi",
						Version: "3.2.1-r6",
					},
					{
						Name:    "libgcc",
						Version: "8.3.0-r0",
					},
					{
						Name:    "libgcrypt",
						Version: "1.8.4-r0",
					},
					{
						Name:    "libgomp",
						Version: "8.3.0-r0",
					},
					{
						Name:    "libgpg-error",
						Version: "1.33-r0",
					},
					{
						Name:    "libksba",
						Version: "1.3.5-r0",
					},
					{
						Name:    "libldap",
						Version: "2.4.47-r2",
					},
					{
						Name:    "libmagic",
						Version: "5.36-r0",
					},
					{
						Name:    "libsasl",
						Version: "2.1.27-r1",
					},
					{
						Name:    "libsodium",
						Version: "1.0.16-r0",
					},
					{
						Name:    "libsodium-dev",
						Version: "1.0.16-r0",
					},
					{
						Name:    "libssh2",
						Version: "1.8.2-r0",
					},
					{
						Name:    "libssh2-dev",
						Version: "1.8.2-r0",
					},
					{
						Name:    "libssl1.1",
						Version: "1.1.1b-r1",
					},
					{
						Name:    "libstdc++",
						Version: "8.3.0-r0",
					},
					{
						Name:    "libtasn1",
						Version: "4.13-r0",
					},
					{
						Name:    "libunistring",
						Version: "0.9.10-r0",
					},
					{
						Name:    "libuuid",
						Version: "2.33-r0",
					},
					{
						Name:    "libxml2",
						Version: "2.9.9-r1",
					},
					{
						Name:    "libxml2-dev",
						Version: "2.9.9-r1",
					},
					{
						Name:    "lz4",
						Version: "1.8.3-r2",
					},
					{
						Name:    "lz4-libs",
						Version: "1.8.3-r2",
					},
					{
						Name:    "m4",
						Version: "1.4.18-r1",
					},
					{
						Name:    "make",
						Version: "4.2.1-r2",
					},
					{
						Name:    "mercurial",
						Version: "4.9.1-r0",
					},
					{
						Name:    "mpc1",
						Version: "1.0.3-r1",
					},
					{
						Name:    "mpfr3",
						Version: "3.1.5-r1",
					},
					{
						Name:    "musl",
						Version: "1.1.20-r4",
					},
					{
						Name:    "musl-dev",
						Version: "1.1.20-r4",
					},
					{
						Name:    "ncurses",
						Version: "6.1_p20190105-r0",
					},
					{
						Name:    "ncurses-dev",
						Version: "6.1_p20190105-r0",
					},
					{
						Name:    "ncurses-libs",
						Version: "6.1_p20190105-r0",
					},
					{
						Name:    "ncurses-terminfo",
						Version: "6.1_p20190105-r0",
					},
					{
						Name:    "ncurses-terminfo-base",
						Version: "6.1_p20190105-r0",
					},
					{
						Name:    "nettle",
						Version: "3.4.1-r0",
					},
					{
						Name:    "nghttp2",
						Version: "1.35.1-r0",
					},
					{
						Name:    "nghttp2-dev",
						Version: "1.35.1-r0",
					},
					{
						Name:    "nghttp2-libs",
						Version: "1.35.1-r0",
					},
					{
						Name:    "npth",
						Version: "1.6-r0",
					},
					{
						Name:    "openldap",
						Version: "2.4.47-r2",
					},
					{
						Name:    "openssh",
						Version: "7.9_p1-r5",
					},
					{
						Name:    "openssh-client",
						Version: "7.9_p1-r5",
					},
					{
						Name:    "openssh-keygen",
						Version: "7.9_p1-r5",
					},
					{
						Name:    "openssh-server",
						Version: "7.9_p1-r5",
					},
					{
						Name:    "openssh-server-common",
						Version: "7.9_p1-r5",
					},
					{
						Name:    "openssh-sftp-server",
						Version: "7.9_p1-r5",
					},
					{
						Name:    "openssl",
						Version: "1.1.1b-r1",
					},
					{
						Name:    "openssl-dev",
						Version: "1.1.1b-r1",
					},
					{
						Name:    "p11-kit",
						Version: "0.23.14-r0",
					},
					{
						Name:    "patch",
						Version: "2.7.6-r4",
					},
					{
						Name:    "pcre2",
						Version: "10.32-r1",
					},
					{
						Name:    "perl",
						Version: "5.26.3-r0",
					},
					{
						Name:    "pinentry",
						Version: "1.1.0-r0",
					},
					{
						Name:    "pkgconf",
						Version: "1.6.0-r0",
					},
					{
						Name:    "python2",
						Version: "2.7.16-r1",
					},
					{
						Name:    "re2c",
						Version: "1.1.1-r0",
					},
					{
						Name:    "readline",
						Version: "7.0.003-r1",
					},
					{
						Name:    "serf",
						Version: "1.3.9-r5",
					},
					{
						Name:    "sqlite",
						Version: "3.26.0-r3",
					},
					{
						Name:    "sqlite-dev",
						Version: "3.26.0-r3",
					},
					{
						Name:    "sqlite-libs",
						Version: "3.26.0-r3",
					},
					{
						Name:    "subversion",
						Version: "1.11.1-r0",
					},
					{
						Name:    "subversion-libs",
						Version: "1.11.1-r0",
					},
					{
						Name:    "tar",
						Version: "1.32-r0",
					},
					{
						Name:    "unzip",
						Version: "6.0-r4",
					},
					{
						Name:    "util-linux",
						Version: "2.33-r0",
					},
					{
						Name:    "wget",
						Version: "1.20.3-r0",
					},
					{
						Name:    "xz",
						Version: "5.2.4-r0",
					},
					{
						Name:    "xz-libs",
						Version: "5.2.4-r0",
					},
					{
						Name:    "zip",
						Version: "3.0-r7",
					},
					{
						Name:    "zlib",
						Version: "1.2.11-r1",
					},
					{
						Name:    "zlib-dev",
						Version: "1.2.11-r1",
					},
				},
			},
		},
	}
)

func TestAnalyze(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		content, err := os.ReadFile("testdata/history_v3.9.json")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		res.WriteHeader(http.StatusOK)
		res.Write(content)
		return
	}))
	defer testServer.Close()

	type args struct {
		targetOS types.OS
		config   *v1.ConfigFile
	}
	var tests = map[string]struct {
		args                args
		apkIndexArchivePath string
		want                *analyzer.AnalysisResult
	}{
		"old": {
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.9.1",
				},
				config: oldAlpineConfig,
			},
			apkIndexArchivePath: "file://testdata/history_v%s.json",
			want:                nil,
		},
		"new": {
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.9.1",
				},
				config: alpineConfig,
			},
			apkIndexArchivePath: "file://testdata/history_v%s.json",
			want:                wantPkgs,
		},
		"https": {
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "",
				},
				config: alpineConfig,
			},
			apkIndexArchivePath: testServer.URL + "%v",
			want:                wantPkgs,
		},
	}
	for testName, v := range tests {
		t.Run(testName, func(t *testing.T) {
			apkIndexArchiveURL = v.apkIndexArchivePath
			a := alpineCmdAnalyzer{}
			actual, _ := a.Analyze(analyzer.ConfigAnalysisInput{
				OS:     v.args.targetOS,
				Config: v.args.config,
			})
			if actual != nil {
				require.Equal(t, 1, len(actual.PackageInfos))
				sort.Sort(actual.PackageInfos[0].Packages)
			}
			assert.Equal(t, v.want, actual)
		})
	}
}

func TestParseCommand(t *testing.T) {
	var tests = map[string]struct {
		command  string
		envs     map[string]string
		expected []string
	}{
		"no package": {
			command:  "/bin/sh -c #(nop) ADD file:49f9e47e678d868d5b023482aa8dded71276a241a665c4f8b55ca77269321b34 in / ",
			envs:     nil,
			expected: nil,
		},
		"no-cache": {
			command: "/bin/sh -c apk add --no-cache --virtual .persistent-deps \t\tca-certificates \t\tcurl \t\ttar \t\txz \t\tlibressl",
			envs:    nil,
			expected: []string{
				"ca-certificates",
				"curl",
				"tar",
				"xz",
				"libressl",
			},
		},
		// TODO: support $runDeps
		"joined by &&": {
			command:  `/bin/sh -c apk add --no-cache --virtual .build-deps zlib-dev  && docker-php-ext-install zip  && runDeps=\"$(     scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions     | tr ',' '\\n'     | sort -u     | awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }'     )\"  && apk add --virtual .composer-phpext-rundeps $runDeps  && apk del .build-deps`,
			envs:     nil,
			expected: []string{"zlib-dev"},
		},
		"joined by ;": {
			command: "/bin/sh -c set -xe; \t\tapk add --no-cache --virtual .fetch-deps \t\tgnupg \t\twget \t; \t\tmkdir -p /usr/src; \tcd /usr/src; \t\twget -O php.tar.xz \"$PHP_URL\"; \t\tif [ -n \"$PHP_SHA256\" ]; then \t\techo \"$PHP_SHA256 *php.tar.xz\" | sha256sum -c -; \tfi; \tif [ -n \"$PHP_MD5\" ]; then \t\techo \"$PHP_MD5 *php.tar.xz\" | md5sum -c -; \tfi; \t\tif [ -n \"$PHP_ASC_URL\" ]; then \t\twget -O php.tar.xz.asc \"$PHP_ASC_URL\"; \t\texport GNUPGHOME=\"$(mktemp -d)\"; \t\tfor key in $GPG_KEYS; do \t\t\tgpg --keyserver ha.pool.sks-keyservers.net --recv-keys \"$key\"; \t\tdone; \t\tgpg --batch --verify php.tar.xz.asc php.tar.xz; \t\tcommand -v gpgconf > /dev/null && gpgconf --kill all; \t\trm -rf \"$GNUPGHOME\"; \tfi; \t\tapk del .fetch-deps",
			envs:    nil,
			expected: []string{
				"gnupg",
				"wget",
			},
		},
		"ENV": {
			command: "/bin/sh -c set -xe \t&& apk add --no-cache --virtual .build-deps \t\t$PHPIZE_DEPS \t\tcoreutils \t\tcurl-dev \t\tlibedit-dev \t\tlibressl-dev \t\tlibsodium-dev \t\tlibxml2-dev \t\tsqlite-dev",
			envs: map[string]string{
				"$PHPIZE_DEPS": "autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
			},
			expected: []string{
				"autoconf",
				"dpkg-dev",
				"dpkg",
				"file",
				"g++",
				"gcc",
				"libc-dev",
				"make",
				"pkgconf",
				"re2c",
				"coreutils",
				"curl-dev",
				"libedit-dev",
				"libressl-dev",
				"libsodium-dev",
				"libxml2-dev",
				"sqlite-dev",
			},
		},
	}
	analyzer := alpineCmdAnalyzer{}
	for testName, v := range tests {
		actual := analyzer.parseCommand(v.command, v.envs)
		assert.Equal(t, v.expected, actual, "[%s]\n%s", testName, pretty.Compare(v.expected, actual))
	}
}

func TestResolveDependency(t *testing.T) {
	var tests = map[string]struct {
		pkgName             string
		apkIndexArchivePath string
		expected            map[string]struct{}
	}{
		"low": {
			pkgName:             "libblkid",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"libblkid": {},
				"libuuid":  {},
				"musl":     {},
			},
		},
		"medium": {
			pkgName:             "libgcab",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"busybox":  {},
				"libblkid": {},
				"libuuid":  {},
				"musl":     {},
				"libmount": {},
				"pcre":     {},
				"glib":     {},
				"libgcab":  {},
				"libintl":  {},
				"zlib":     {},
				"libffi":   {},
			},
		},
		"high": {
			pkgName:             "postgresql",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"busybox":               {},
				"ncurses-terminfo-base": {},
				"ncurses-terminfo":      {},
				"libedit":               {},
				"db":                    {},
				"libsasl":               {},
				"libldap":               {},
				"libpq":                 {},
				"postgresql-client":     {},
				"tzdata":                {},
				"libxml2":               {},
				"postgresql":            {},
				"musl":                  {},
				"libcrypto1.1":          {},
				"libssl1.1":             {},
				"ncurses-libs":          {},
				"zlib":                  {},
			},
		},
		"package alias": {
			pkgName:             "sqlite-dev",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"sqlite-dev":  {},
				"sqlite-libs": {},
				"pkgconf":     {}, // pkgconfig => pkgconf
				"musl":        {},
			},
		},
		"circular dependencies": {
			pkgName:             "nodejs",
			apkIndexArchivePath: "testdata/history_v3.7.json",
			expected: map[string]struct{}{
				"busybox":               {},
				"c-ares":                {},
				"ca-certificates":       {},
				"http-parser":           {},
				"libcrypto1.0":          {},
				"libgcc":                {},
				"libressl2.6-libcrypto": {},
				"libssl1.0":             {},
				"libstdc++":             {},
				"libuv":                 {},
				"musl":                  {},
				"nodejs":                {},
				"nodejs-npm":            {},
				"zlib":                  {},
			},
		},
	}
	analyzer := alpineCmdAnalyzer{}
	for testName, v := range tests {
		f, err := os.Open(v.apkIndexArchivePath)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		apkIndexArchive := &apkIndex{}
		if err = json.NewDecoder(f).Decode(&apkIndexArchive); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		circularDependencyCheck := map[string]struct{}{}
		pkgs := analyzer.resolveDependency(apkIndexArchive, v.pkgName, circularDependencyCheck)
		actual := map[string]struct{}{}
		for _, pkg := range pkgs {
			actual[pkg] = struct{}{}
		}
		if !reflect.DeepEqual(v.expected, actual) {
			t.Errorf("[%s]\n%s", testName, pretty.Compare(v.expected, actual))
		}
	}
}

func TestGuessVersion(t *testing.T) {
	var tests = map[string]struct {
		apkIndexArchive *apkIndex
		pkgs            []string
		createdAt       time.Time
		expected        []types.Package
	}{
		"normal": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"busybox": {
						Versions: map[string]int{
							"1.24.2-r0": 100,
							"1.24.2-r1": 200,
							"1.24.2-r2": 300,
						},
					},
				},
			},
			pkgs:      []string{"busybox"},
			createdAt: time.Unix(200, 0),
			expected: []types.Package{
				{
					Name:    "busybox",
					Version: "1.24.2-r1",
				},
			},
		},
		"unmatched version": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"busybox": {
						Versions: map[string]int{
							"1.24.2-r0": 100,
							"1.24.2-r1": 200,
							"1.24.2-r2": 300,
						},
					},
				},
			},
			pkgs:      []string{"busybox"},
			createdAt: time.Unix(50, 0),
			expected:  nil,
		},
		"unmatched package": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"busybox": {
						Versions: map[string]int{
							"1.24.2-r0": 100,
							"1.24.2-r1": 200,
							"1.24.2-r2": 300,
						},
					},
				},
			},
			pkgs: []string{
				"busybox",
				"openssl",
			},
			createdAt: time.Unix(200, 0),
			expected: []types.Package{
				{
					Name:    "busybox",
					Version: "1.24.2-r1",
				},
			},
		},
		"origin": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"sqlite-dev": {
						Versions: map[string]int{
							"3.26.0-r0": 100,
							"3.26.0-r1": 200,
							"3.26.0-r2": 300,
							"3.26.0-r3": 400,
						},
						Origin: "sqlite",
					},
				},
			},
			pkgs:      []string{"sqlite-dev"},
			createdAt: time.Unix(500, 0),
			expected: []types.Package{
				{
					Name:    "sqlite-dev",
					Version: "3.26.0-r3",
				},
				{
					Name:    "sqlite",
					Version: "3.26.0-r3",
				},
			},
		},
	}
	analyzer := alpineCmdAnalyzer{}
	for testName, v := range tests {
		actual := analyzer.guessVersion(v.apkIndexArchive, v.pkgs, v.createdAt)
		if !reflect.DeepEqual(v.expected, actual) {
			t.Errorf("[%s]\n%s", testName, pretty.Compare(v.expected, actual))
		}
	}
}
