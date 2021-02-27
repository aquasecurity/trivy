[Clair][clair] uses [alpine-secdb][alpine-secdb].
However, the purpose of this database is to make it possible to know what packages has backported fixes.
As README says, it is not a complete database of all security issues in Alpine.

`Trivy` collects vulnerability information in Alpine Linux from [Alpine Linux aports repository][aports].
Then, those vulnerabilities will be saved on [vuln-list][vuln-list].

`alpine-secdb` has 6959 vulnerabilities (as of 2019/05/12).
`vuln-list` has 11101 vulnerabilities related to Alpine Linux (as of 2019/05/12).
There is a difference in detection accuracy because the number of vulnerabilities is nearly doubled.

In addition, `Trivy` analyzes the middle layers as well to find out which version of the library was used for static linking.

`Clair` can not handle the following cases because it analyzes the image after applying all layers.

```
RUN apk add --no-cache sqlite-dev \
 && wget https://xxx/yyy.tar.gz \
 && tar zxvf yyy.tar.gz && cd yyy \
 && make && make install \
 && apk del sqlite-dev
```

And as many people know, it is difficult to select a `Clair` client because many clients are deprecated.

Trivy is a stand-alone tool and can scan very fast. This means it's very easy to use in CI/CD.

Finally, `Trivy` can also detect vulnerabilities in application dependent libraries such as Bundler, Composer, Pipenv, etc.

[clair]: https://github.com/coreos/clair
[alpine-secdb]: https://github.com/alpinelinux/alpine-secdb/
[aports]: https://gitlab.alpinelinux.org/alpine/aports
[vuln-list]: https://github.com/aquasecurity/vuln-list/tree/main/alpine
